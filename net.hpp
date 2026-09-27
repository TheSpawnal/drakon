#pragma once
#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "ring.hpp"

// Coarse application-layer classification, inferred from transport ports only.
// This is a hint for the operator, not a real L7 dissection.
enum L7Hint : uint16_t {
    L7_NONE = 0, L7_DNS, L7_MDNS, L7_HTTP, L7_TLS, L7_QUIC, L7_SSH,
    L7_NTP, L7_OLLAMA, L7_LLM_API, L7_UI
};
const char* l7_name(uint16_t h);

// A single captured frame reduced to L2-L4 metadata. No payload is retained:
// the snap length is set short and only header fields are copied out, so the
// tool never holds message contents in memory or on disk.
struct PacketRecord {
    double ts = 0.0;                  // seconds since epoch (pcap timestamp)
    uint8_t family = 0;               // AF_INET or AF_INET6
    uint8_t l4 = 0;                   // IPPROTO_TCP / UDP / ICMP ...
    uint8_t tcp_flags = 0;
    uint8_t saddr[16] = {0};
    uint8_t daddr[16] = {0};
    uint16_t sport = 0, dport = 0;
    uint32_t length = 0;              // on-wire length
    uint16_t l7 = L7_NONE;
    int8_t direction = 0;             // +1 outbound, -1 inbound, 0 local/other
};

// Bidirectional conversation, keyed on the canonical endpoint pair so A->B and
// B->A aggregate into one row.
struct FlowStat {
    uint8_t family = 0, l4 = 0;
    uint8_t a_addr[16] = {0}, b_addr[16] = {0};
    uint16_t a_port = 0, b_port = 0;
    uint64_t bytes_ab = 0, bytes_ba = 0;
    uint64_t pkts_ab = 0, pkts_ba = 0;
    double first_ts = 0.0, last_ts = 0.0;
    uint16_t l7 = L7_NONE;
};

struct NetDevice { std::string name, description; };

class NetCapture {
public:
    ~NetCapture();

    static std::vector<NetDevice> list_devices();

    // Opens the capture handle and, on success, drops all process
    // capabilities before spawning the reader thread. `snaplen` is clamped to
    // header-only sizes; `promisc` defaults off so only traffic the host would
    // normally see is captured. `filter` is a BPF expression.
    bool start(const std::string& device, const std::string& filter,
               bool promisc, int snaplen);
    void stop();

    // Move up to `max` records from the ring into `out` (appends). Cheap; the
    // UI calls this once per frame.
    size_t drain(std::vector<PacketRecord>& out, size_t max);

    std::vector<FlowStat> flows_snapshot();

    uint64_t total_pkts() const { return total_pkts_.load(); }
    uint64_t total_bytes() const { return total_bytes_.load(); }
    uint64_t in_bytes() const { return in_bytes_.load(); }
    uint64_t out_bytes() const { return out_bytes_.load(); }
    uint64_t ring_dropped() const { return ring_.dropped(); }
    uint64_t kernel_dropped();        // queries pcap_stats

    bool running() const { return run_.load(); }
    const std::string& error() const { return error_; }
    const std::string& device() const { return device_; }

private:
    void loop();

    void* pcap_ = nullptr;            // pcap_t*, opaque in header
    int datalink_ = 0;
    std::thread th_;
    std::atomic<bool> run_{false};
    std::string error_, device_;

    SpscRing<PacketRecord, 1u << 14> ring_;

    std::mutex flows_mtx_;
    std::vector<FlowStat> flows_;     // small, bounded set of live conversations

    std::atomic<uint64_t> total_pkts_{0}, total_bytes_{0};
    std::atomic<uint64_t> in_bytes_{0}, out_bytes_{0};

    // Local addresses, gathered once at start, used to classify direction.
    std::vector<std::array<uint8_t, 16>> local_v4_, local_v6_;
};
