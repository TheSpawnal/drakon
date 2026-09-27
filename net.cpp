#include "net.hpp"

#include "privilege.hpp"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <sys/socket.h>

#include <algorithm>
#include <chrono>
#include <cstring>

// ---------------------------------------------------------------------------
// L7 port hints
// ---------------------------------------------------------------------------
const char* l7_name(uint16_t h) {
    switch (h) {
        case L7_DNS: return "DNS";
        case L7_MDNS: return "mDNS";
        case L7_HTTP: return "HTTP";
        case L7_TLS: return "TLS";
        case L7_QUIC: return "QUIC";
        case L7_SSH: return "SSH";
        case L7_NTP: return "NTP";
        case L7_OLLAMA: return "Ollama";
        case L7_LLM_API: return "LLM-API";
        case L7_UI: return "Web-UI";
        default: return "";
    }
}

namespace {

uint16_t l7_for(uint16_t proto, uint16_t sp, uint16_t dp) {
    auto is = [&](uint16_t p) { return sp == p || dp == p; };
    if (is(53)) return L7_DNS;
    if (is(5353)) return L7_MDNS;
    if (is(123)) return L7_NTP;
    if (is(22)) return L7_SSH;
    if (is(11434)) return L7_OLLAMA;                       // ollama default
    if (proto == IPPROTO_UDP && is(443)) return L7_QUIC;
    if (proto == IPPROTO_TCP && is(443)) return L7_TLS;
    if (is(80) || is(8080)) return L7_HTTP;
    if (is(8000) || is(5000) || is(1234) || is(8001))       // common local APIs
        return L7_LLM_API;
    if (is(3000) || is(7860) || is(8188) || is(5173))       // common local UIs
        return L7_UI;
    return L7_NONE;
}

// A cursor that refuses to read past the captured bytes. Every accessor checks
// bounds first; the dissector below never dereferences without going through
// it. This is the whole game for a parser fed attacker-influenced input.
struct Cursor {
    const uint8_t* p;
    uint32_t caplen;
    uint32_t off = 0;
    bool have(uint32_t n) const { return off + n <= caplen; }
    uint8_t u8(uint32_t at) const { return p[at]; }
    uint16_t be16(uint32_t at) const {
        return static_cast<uint16_t>((p[at] << 8) | p[at + 1]);
    }
};

int link_l3_offset(int dlt, const Cursor& c, uint16_t* ethertype) {
    switch (dlt) {
        case DLT_EN10MB: {
            if (!c.have(14)) return -1;
            uint16_t et = c.be16(12);
            uint32_t base = 14;
            if (et == 0x8100 || et == 0x88A8) {  // 802.1Q / QinQ
                if (!c.have(18)) return -1;
                et = c.be16(16);
                base = 18;
            }
            *ethertype = et;
            return static_cast<int>(base);
        }
        case DLT_LINUX_SLL:
            if (!c.have(16)) return -1;
            *ethertype = c.be16(14);
            return 16;
#ifdef DLT_LINUX_SLL2
        case DLT_LINUX_SLL2:
            if (!c.have(20)) return -1;
            *ethertype = c.be16(0);   // protocol type is the first field in SLL2
            return 20;
#endif
        case DLT_RAW: {
            if (!c.have(1)) return -1;
            const uint8_t ver = c.u8(0) >> 4;
            *ethertype = (ver == 6) ? 0x86DD : 0x0800;
            return 0;
        }
        default:
            return -1;
    }
}

// Walk a bounded chain of IPv6 extension headers to reach the transport header.
// Returns the transport protocol and sets *l4off, or -1 if the chain runs past
// the capture.
int ipv6_transport(const Cursor& c, uint32_t l3, uint32_t* l4off) {
    if (!c.have(l3 + 40)) return -1;
    uint8_t next = c.u8(l3 + 6);
    uint32_t off = l3 + 40;
    for (int i = 0; i < 8; ++i) {  // hard cap on chain length
        switch (next) {
            case 0:    // hop-by-hop
            case 43:   // routing
            case 60: { // destination options
                if (!c.have(off + 2)) return -1;
                const uint32_t len = (c.u8(off + 1) + 1u) * 8u;
                next = c.u8(off);
                off += len;
                break;
            }
            case 44: { // fragment (fixed 8 bytes)
                if (!c.have(off + 8)) return -1;
                next = c.u8(off);
                off += 8;
                break;
            }
            default:
                *l4off = off;
                return next;
        }
        if (off > c.caplen) return -1;
    }
    return -1;
}

}  // namespace

// ---------------------------------------------------------------------------
// Direction classification helpers
// ---------------------------------------------------------------------------
namespace {
bool addr_in(const std::vector<std::array<uint8_t, 16>>& set,
             const uint8_t* a, size_t len) {
    for (const auto& e : set)
        if (std::memcmp(e.data(), a, len) == 0) return true;
    return false;
}
}  // namespace

// ---------------------------------------------------------------------------
// NetCapture
// ---------------------------------------------------------------------------
NetCapture::~NetCapture() { stop(); }

std::vector<NetDevice> NetCapture::list_devices() {
    std::vector<NetDevice> out;
    pcap_if_t* all = nullptr;
    char err[PCAP_ERRBUF_SIZE] = {0};
    if (pcap_findalldevs(&all, err) != 0) return out;
    for (pcap_if_t* d = all; d; d = d->next)
        out.push_back({d->name ? d->name : "", d->description ? d->description : ""});
    pcap_freealldevs(all);
    return out;
}

bool NetCapture::start(const std::string& device, const std::string& filter,
                       bool promisc, int snaplen) {
    device_ = device;
    char err[PCAP_ERRBUF_SIZE] = {0};

    // Gather local addresses so packets can be labelled inbound/outbound.
    if (ifaddrs* ifa = nullptr; getifaddrs(&ifa) == 0) {
        for (ifaddrs* it = ifa; it; it = it->ifa_next) {
            if (!it->ifa_addr) continue;
            if (it->ifa_addr->sa_family == AF_INET) {
                std::array<uint8_t, 16> a{};
                auto* s = reinterpret_cast<sockaddr_in*>(it->ifa_addr);
                std::memcpy(a.data(), &s->sin_addr, 4);
                local_v4_.push_back(a);
            } else if (it->ifa_addr->sa_family == AF_INET6) {
                std::array<uint8_t, 16> a{};
                auto* s = reinterpret_cast<sockaddr_in6*>(it->ifa_addr);
                std::memcpy(a.data(), &s->sin6_addr, 16);
                local_v6_.push_back(a);
            }
        }
        freeifaddrs(ifa);
    }

    pcap_t* h = pcap_create(device.c_str(), err);
    if (!h) { error_ = err; return false; }

    // Header-only capture: clamp the snap length so payloads are never copied.
    const int snap = std::clamp(snaplen, 96, 262);
    pcap_set_snaplen(h, snap);
    pcap_set_promisc(h, promisc ? 1 : 0);
    pcap_set_timeout(h, 100);           // ms; bounds latency of the reader loop
    pcap_set_immediate_mode(h, 1);      // deliver frames as they arrive

    if (int rc = pcap_activate(h); rc < 0) {
        error_ = pcap_geterr(h);
        if (error_.empty()) error_ = pcap_statustostr(rc);
        pcap_close(h);
        return false;
    }

    // The one privileged action is done. Shed every capability now, before a
    // single byte of network data is parsed.
    drop_all_capabilities();

    if (!filter.empty()) {
        bpf_program prog{};
        if (pcap_compile(h, &prog, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_setfilter(h, &prog);
            pcap_freecode(&prog);
        } else {
            error_ = std::string("filter rejected: ") + pcap_geterr(h);
            // Non-fatal: capture proceeds unfiltered, but the UI shows the note.
        }
    }

    datalink_ = pcap_datalink(h);
    pcap_ = h;
    run_ = true;
    th_ = std::thread(&NetCapture::loop, this);
    return true;
}

void NetCapture::stop() {
    if (run_.exchange(false)) {
        if (pcap_) pcap_breakloop(static_cast<pcap_t*>(pcap_));
        if (th_.joinable()) th_.join();
        if (pcap_) { pcap_close(static_cast<pcap_t*>(pcap_)); pcap_ = nullptr; }
    }
}

void NetCapture::loop() {
    pcap_t* h = static_cast<pcap_t*>(pcap_);
    while (run_.load()) {
        pcap_pkthdr* hdr = nullptr;
        const u_char* data = nullptr;
        const int rc = pcap_next_ex(h, &hdr, &data);
        if (rc == 0) continue;          // timeout, re-check run flag
        if (rc < 0) break;              // error or breakloop

        Cursor c{data, hdr->caplen};
        uint16_t ethertype = 0;
        const int l3i = link_l3_offset(datalink_, c, &ethertype);
        if (l3i < 0) continue;
        const uint32_t l3 = static_cast<uint32_t>(l3i);

        PacketRecord r;
        r.ts = hdr->ts.tv_sec + hdr->ts.tv_usec / 1e6;
        r.length = hdr->len;

        uint32_t l4 = 0;
        if (ethertype == 0x0800) {                        // IPv4
            if (!c.have(l3 + 20)) continue;
            const uint8_t ihl = (c.u8(l3) & 0x0F) * 4u;
            if (ihl < 20 || !c.have(l3 + ihl)) continue;
            r.family = AF_INET;
            r.l4 = c.u8(l3 + 9);
            std::memcpy(r.saddr, &data[l3 + 12], 4);
            std::memcpy(r.daddr, &data[l3 + 16], 4);
            l4 = l3 + ihl;
        } else if (ethertype == 0x86DD) {                 // IPv6
            uint32_t off = 0;
            const int proto = ipv6_transport(c, l3, &off);
            if (proto < 0) continue;
            r.family = AF_INET6;
            r.l4 = static_cast<uint8_t>(proto);
            std::memcpy(r.saddr, &data[l3 + 8], 16);
            std::memcpy(r.daddr, &data[l3 + 24], 16);
            l4 = off;
        } else {
            continue;                                     // not IP; ignore
        }

        if (r.l4 == IPPROTO_TCP) {
            if (!c.have(l4 + 20)) continue;
            r.sport = c.be16(l4);
            r.dport = c.be16(l4 + 2);
            r.tcp_flags = c.u8(l4 + 13);
        } else if (r.l4 == IPPROTO_UDP) {
            if (!c.have(l4 + 8)) continue;
            r.sport = c.be16(l4);
            r.dport = c.be16(l4 + 2);
        }
        r.l7 = l7_for(r.l4, r.sport, r.dport);

        // Direction relative to this host.
        const size_t alen = (r.family == AF_INET) ? 4 : 16;
        const auto& lset = (r.family == AF_INET) ? local_v4_ : local_v6_;
        const bool src_local = addr_in(lset, r.saddr, alen);
        const bool dst_local = addr_in(lset, r.daddr, alen);
        if (src_local && !dst_local) { r.direction = +1; out_bytes_ += r.length; }
        else if (dst_local && !src_local) { r.direction = -1; in_bytes_ += r.length; }
        else r.direction = 0;

        total_pkts_++;
        total_bytes_ += r.length;
        ring_.push(r);

        // Update the flow table under lock. Canonical key: the numerically
        // lower (addr, port) endpoint is A, so both directions collapse to one.
        {
            const int cmp = std::memcmp(r.saddr, r.daddr, alen);
            const bool src_is_a =
                (cmp < 0) || (cmp == 0 && r.sport <= r.dport);

            std::lock_guard<std::mutex> lk(flows_mtx_);
            FlowStat* fs = nullptr;
            for (auto& f : flows_) {
                if (f.family != r.family || f.l4 != r.l4) continue;
                const uint8_t* a = src_is_a ? r.saddr : r.daddr;
                const uint8_t* b = src_is_a ? r.daddr : r.saddr;
                const uint16_t ap = src_is_a ? r.sport : r.dport;
                const uint16_t bp = src_is_a ? r.dport : r.sport;
                if (std::memcmp(f.a_addr, a, alen) == 0 &&
                    std::memcmp(f.b_addr, b, alen) == 0 &&
                    f.a_port == ap && f.b_port == bp) {
                    fs = &f;
                    break;
                }
            }
            if (!fs) {
                if (flows_.size() >= 4096) {  // evict the least-recently-seen
                    auto oldest = std::min_element(
                        flows_.begin(), flows_.end(),
                        [](const FlowStat& x, const FlowStat& y) {
                            return x.last_ts < y.last_ts;
                        });
                    *oldest = FlowStat{};     // min_element on non-empty: valid
                    fs = &(*oldest);
                } else {
                    flows_.emplace_back();
                    fs = &flows_.back();
                }
                fs->family = r.family;
                fs->l4 = r.l4;
                fs->l7 = r.l7;
                fs->first_ts = r.ts;
                std::memcpy(fs->a_addr, src_is_a ? r.saddr : r.daddr, alen);
                std::memcpy(fs->b_addr, src_is_a ? r.daddr : r.saddr, alen);
                fs->a_port = src_is_a ? r.sport : r.dport;
                fs->b_port = src_is_a ? r.dport : r.sport;
            }
            fs->last_ts = r.ts;
            if (src_is_a) { fs->bytes_ab += r.length; fs->pkts_ab++; }
            else { fs->bytes_ba += r.length; fs->pkts_ba++; }
        }
    }
    run_ = false;
}

size_t NetCapture::drain(std::vector<PacketRecord>& out, size_t max) {
    size_t n = 0;
    PacketRecord r;
    while (n < max && ring_.pop(r)) { out.push_back(r); ++n; }
    return n;
}

std::vector<FlowStat> NetCapture::flows_snapshot() {
    std::lock_guard<std::mutex> lk(flows_mtx_);
    return flows_;
}

uint64_t NetCapture::kernel_dropped() {
    if (!pcap_) return 0;
    pcap_stat st{};
    if (pcap_stats(static_cast<pcap_t*>(pcap_), &st) == 0)
        return st.ps_drop + st.ps_ifdrop;
    return 0;
}
