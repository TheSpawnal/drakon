// drakon - native AI telemetry and packet cockpit
//
// Three worker contexts feed one immediate-mode UI:
//   - GpuMonitor : NVML device + per-process readings on its own thread
//   - NetCapture : libpcap reader thread, bounded dissector, flow table
//   - Sysstat    : cheap /proc host context, sampled inline
// The UI thread only ever reads snapshots and drains a lock-free ring, so
// rendering can never stall capture.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <string>
#include <vector>

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "implot.h"
#include <GLFW/glfw3.h>

#include "gpu.hpp"
#include "net.hpp"
#include "privilege.hpp"
#include "sysstat.hpp"
#include "theme.hpp"
#include "tsc.hpp"

using clk = std::chrono::steady_clock;

// ---------------------------------------------------------------------------
// small formatting helpers
// ---------------------------------------------------------------------------
namespace {

std::string fmt_bytes(double b) {
    const char* u[] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0;
    while (b >= 1024.0 && i < 4) { b /= 1024.0; ++i; }
    char o[32];
    std::snprintf(o, sizeof(o), "%.1f %s", b, u[i]);
    return o;
}

std::string fmt_addr(uint8_t fam, const uint8_t* a, uint16_t port) {
    char ip[INET6_ADDRSTRLEN] = {0};
    inet_ntop(fam == AF_INET ? AF_INET : AF_INET6, a, ip, sizeof(ip));
    char o[INET6_ADDRSTRLEN + 16];
    if (port)
        std::snprintf(o, sizeof(o), fam == AF_INET ? "%s:%u" : "[%s]:%u", ip, port);
    else
        std::snprintf(o, sizeof(o), "%s", ip);
    return o;
}

const char* proto_name(uint8_t p) {
    switch (p) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_ICMPV6: return "ICMPv6";
        default: return "IP";
    }
}

std::string tcp_flags_str(uint8_t f) {
    if (!f) return "";
    std::string s;
    const char* n = "FSRPAUEC";  // FIN SYN RST PSH ACK URG ECE CWR
    for (int i = 0; i < 8; ++i)
        if (f & (1u << i)) s += n[i];
    return s;
}

// Wrapped ring for ImPlot time series.
struct Roll {
    int cap;
    std::vector<float> t, v;
    int head = 0;
    bool full = false;
    explicit Roll(int c = 1800) : cap(c), t(c), v(c) {}
    void add(float ts, float val) {
        t[head] = ts;
        v[head] = val;
        head = (head + 1) % cap;
        if (head == 0) full = true;
    }
    int count() const { return full ? cap : head; }
    int offset() const { return full ? head : 0; }
};

void plot_series(const char* id, const char* label, Roll& r, double now,
                 double window, bool clamp01, float px_h) {
    if (ImPlot::BeginPlot(id, ImVec2(-1, px_h),
                          ImPlotFlags_NoLegend | ImPlotFlags_NoMenus |
                              ImPlotFlags_NoBoxSelect | ImPlotFlags_NoTitle)) {
        ImPlot::SetupAxes(nullptr, nullptr,
                          ImPlotAxisFlags_NoTickLabels,
                          clamp01 ? ImPlotAxisFlags_Lock : ImPlotAxisFlags_AutoFit);
        ImPlot::SetupAxisLimits(ImAxis_X1, now - window, now, ImGuiCond_Always);
        if (clamp01) ImPlot::SetupAxisLimits(ImAxis_Y1, 0, 100, ImGuiCond_Always);
        if (r.count() > 1)
            ImPlot::PlotLine(label, r.t.data(), r.v.data(), r.count(), 0,
                             r.offset(), sizeof(float));
        ImPlot::EndPlot();
    }
}

double wall_now() {
    timeval tv{};
    gettimeofday(&tv, nullptr);
    return tv.tv_sec + tv.tv_usec / 1e6;
}

void glfw_err(int code, const char* desc) {
    std::fprintf(stderr, "glfw error %d: %s\n", code, desc);
}

}  // namespace

int main(int argc, char** argv) {
    std::string device = "any";
    std::string filter = "ip or ip6";
    int snaplen = 128;
    bool promisc = false;
    bool capture = true;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* def) {
            return (i + 1 < argc) ? std::string(argv[++i]) : std::string(def);
        };
        if (a == "--device") device = next("any");
        else if (a == "--filter") filter = next("");
        else if (a == "--snaplen") snaplen = std::stoi(next("128"));
        else if (a == "--promisc") promisc = true;
        else if (a == "--no-capture") capture = false;
        else if (a == "--help") {
            std::printf(
                "drakon [--device NAME] [--filter BPF] [--snaplen N]\n"
                "       [--promisc] [--no-capture]\n"
                "  default device 'any' includes loopback, so a local model\n"
                "  server on 127.0.0.1 is visible. Header-only capture; no\n"
                "  payloads are stored.\n");
            return 0;
        }
    }

    glfwSetErrorCallback(glfw_err);
    if (!glfwInit()) { std::fprintf(stderr, "glfwInit failed\n"); return 1; }
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    GLFWwindow* win = glfwCreateWindow(1400, 900, "drakon", nullptr, nullptr);
    if (!win) { std::fprintf(stderr, "window creation failed\n"); glfwTerminate(); return 1; }
    glfwMakeContextCurrent(win);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImPlot::CreateContext();
    ImGui::GetIO().ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    apply_theme();
    ImGui_ImplGlfw_InitForOpenGL(win, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    GpuMonitor gpu;
    const bool gpu_ok = gpu.start(500);

    NetCapture net;
    bool net_ok = false;
    if (capture) {
        net_ok = net.start(device, filter, promisc, snaplen);
        std::fprintf(stderr, "capture: device=%s filter=\"%s\" %s\n",
                     device.c_str(), filter.c_str(),
                     net_ok ? "active" : net.error().c_str());
    }
    std::fprintf(stderr, "gpu: %s\n", gpu_ok ? "nvml active" : gpu.error().c_str());

    Sysstat sys;
    const double tsc_hz = estimate_tsc_hz();

    // rolling series
    Roll r_util, r_temp, r_pow, r_vram, r_cpu, r_ram, r_in, r_out;
    // packet display buffer (metadata only)
    std::deque<PacketRecord> pkts;
    std::vector<PacketRecord> drained;
    char pkt_filter[128] = {0};
    bool pause_display = false;

    const auto t0 = clk::now();
    auto now_s = [&] {
        return std::chrono::duration<double>(clk::now() - t0).count();
    };
    const double app_epoch = wall_now();

    double next_plot = 0.0, next_rate = 0.0;
    uint64_t prev_in = 0, prev_out = 0;
    double prev_rate_t = 0.0;
    double in_rate = 0.0, out_rate = 0.0;

    uint64_t frame_cycles = 0;

    while (!glfwWindowShouldClose(win)) {
        const uint64_t c_begin = rdtsc_serialised();
        glfwPollEvents();

        const double now = now_s();

        // ---- sampling cadence -------------------------------------------
        GpuSample g = gpu_ok ? gpu.snapshot() : GpuSample{};
        SysSample ss = sys.sample();

        if (now >= next_plot) {
            next_plot = now + 0.25;
            if (g.valid) {
                r_util.add((float)now, (float)g.util_gpu);
                r_temp.add((float)now, (float)g.temp_c);
                r_pow.add((float)now, g.power_mw / 1000.0f);
                float vpct = g.mem_total ? 100.0f * g.mem_used / g.mem_total : 0.0f;
                r_vram.add((float)now, vpct);
            }
            r_cpu.add((float)now, (float)ss.cpu_pct);
            float rpct = ss.mem_total_kb
                             ? 100.0f * ss.mem_used_kb / ss.mem_total_kb
                             : 0.0f;
            r_ram.add((float)now, rpct);
        }

        if (net_ok && now >= next_rate) {
            const uint64_t ib = net.in_bytes(), ob = net.out_bytes();
            const double dt = (prev_rate_t > 0) ? (now - prev_rate_t) : 0.5;
            if (dt > 0) {
                in_rate = (ib - prev_in) / dt;
                out_rate = (ob - prev_out) / dt;
            }
            prev_in = ib; prev_out = ob; prev_rate_t = now;
            next_rate = now + 0.5;
            r_in.add((float)now, (float)(in_rate / 1024.0));   // KB/s
            r_out.add((float)now, (float)(out_rate / 1024.0));
        }

        if (net_ok && !pause_display) {
            drained.clear();
            net.drain(drained, 4000);
            for (auto& p : drained) pkts.push_back(p);
            while (pkts.size() > 4000) pkts.pop_front();
        }

        // ---- frame -------------------------------------------------------
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();
        ImGui::DockSpaceOverViewport(ImGui::GetMainViewport());

        // ================= GPU =================
        ImGui::SetNextWindowPos({12, 30}, ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize({520, 500}, ImGuiCond_FirstUseEver);
        ImGui::Begin("GPU");
        if (!gpu_ok) {
            ImGui::TextDisabled("NVML unavailable: %s", gpu.error().c_str());
        } else if (g.valid) {
            ImGui::TextUnformatted(g.name.c_str());
            ImGui::Separator();

            char ov[48];
            std::snprintf(ov, sizeof(ov), "%u%%", g.util_gpu);
            ImGui::TextDisabled("Compute"); ImGui::SameLine(120);
            ImGui::ProgressBar(g.util_gpu / 100.0f, {-1, 0}, ov);

            std::snprintf(ov, sizeof(ov), "%s / %s", fmt_bytes(g.mem_used).c_str(),
                          fmt_bytes(g.mem_total).c_str());
            float vf = g.mem_total ? (float)g.mem_used / g.mem_total : 0.f;
            ImGui::TextDisabled("VRAM"); ImGui::SameLine(120);
            ImGui::ProgressBar(vf, {-1, 0}, ov);

            std::snprintf(ov, sizeof(ov), "%.1f / %.1f W", g.power_mw / 1000.0,
                          g.power_limit_mw / 1000.0);
            float pf = g.power_limit_mw ? (float)g.power_mw / g.power_limit_mw : 0.f;
            ImGui::TextDisabled("Power"); ImGui::SameLine(120);
            ImGui::ProgressBar(pf, {-1, 0}, ov);

            ImGui::Separator();
            ImGui::Text("Temp   %u C", g.temp_c);   ImGui::SameLine(180);
            ImGui::Text("Fan   %u%%", g.fan_pct);
            ImGui::Text("SM     %u MHz", g.clock_sm_mhz); ImGui::SameLine(180);
            ImGui::Text("Mem   %u MHz", g.clock_mem_mhz);
            ImGui::Text("PCIe   tx %s/s", fmt_bytes(g.pcie_tx_kbs * 1024.0).c_str());
            ImGui::SameLine(180);
            ImGui::Text("rx %s/s", fmt_bytes(g.pcie_rx_kbs * 1024.0).c_str());
            ImGui::Text("NVENC  %u%%", g.enc_util); ImGui::SameLine(180);
            ImGui::Text("NVDEC %u%%", g.dec_util);

            ImGui::Separator();
            ImGui::TextDisabled("Throttle");
            ImGui::SameLine(120);
            auto reasons = decode_throttle(g.throttle_bits);
            bool any = false;
            for (auto& [bit, label] : reasons) {
                if (bit == 0x1 || bit == 0x2) continue;  // idle / app-clock: benign
                any = true;
                ImGui::SameLine();
                ImGui::TextColored({1.0f, 0.62f, 0.28f, 1.0f}, "[%s]", label);
            }
            if (!any) { ImGui::SameLine(); ImGui::TextDisabled("none"); }

            ImGui::Spacing();
            plot_series("##util", "gpu%", r_util, now, 60, true, 90);
            plot_series("##vram", "vram%", r_vram, now, 60, true, 90);
            plot_series("##pow", "W", r_pow, now, 60, false, 90);
            plot_series("##temp", "C", r_temp, now, 60, false, 90);
        }
        ImGui::End();

        // ================= SYSTEM =================
        ImGui::SetNextWindowPos({548, 30}, ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize({300, 500}, ImGuiCond_FirstUseEver);
        ImGui::Begin("System");
        {
            char ov[48];
            std::snprintf(ov, sizeof(ov), "%.0f%%", ss.cpu_pct);
            ImGui::TextDisabled("CPU (%u cores)", ss.cores);
            ImGui::ProgressBar((float)ss.cpu_pct / 100.f, {-1, 0}, ov);
            plot_series("##cpu", "cpu%", r_cpu, now, 60, true, 80);

            double ug = ss.mem_used_kb / 1048576.0, tg = ss.mem_total_kb / 1048576.0;
            std::snprintf(ov, sizeof(ov), "%.1f / %.1f GB", ug, tg);
            float mf = ss.mem_total_kb ? (float)ss.mem_used_kb / ss.mem_total_kb : 0.f;
            ImGui::TextDisabled("Memory");
            ImGui::ProgressBar(mf, {-1, 0}, ov);
            plot_series("##ram", "ram%", r_ram, now, 60, true, 80);

            ImGui::Separator();
            ImGui::Text("Load(1m)  %.2f", ss.load1);
            const double fps = ImGui::GetIO().Framerate;
            ImGui::Text("UI        %.0f fps", fps);
            if (tsc_hz > 0) {
                ImGui::Text("Frame     %.0f kcyc", frame_cycles / 1000.0);
                ImGui::Text("TSC       %.2f GHz", tsc_hz / 1e9);
            }
        }
        ImGui::End();

        // ================= PROCESSES =================
        ImGui::SetNextWindowPos({12, 540}, ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize({520, 340}, ImGuiCond_FirstUseEver);
        ImGui::Begin("GPU processes");
        if (!gpu_ok) {
            ImGui::TextDisabled("NVML unavailable");
        } else {
            ImGui::TextDisabled("%zu process(es) on device", g.procs.size());
            const ImGuiTableFlags tf = ImGuiTableFlags_RowBg |
                ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_SizingStretchProp;
            if (ImGui::BeginTable("procs", 7, tf)) {
                ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 60);
                ImGui::TableSetupColumn("Process");
                ImGui::TableSetupColumn("VRAM", ImGuiTableColumnFlags_WidthFixed, 74);
                ImGui::TableSetupColumn("SM", ImGuiTableColumnFlags_WidthFixed, 44);
                ImGui::TableSetupColumn("MEM", ImGuiTableColumnFlags_WidthFixed, 46);
                ImGui::TableSetupColumn("ENC", ImGuiTableColumnFlags_WidthFixed, 44);
                ImGui::TableSetupColumn("DEC", ImGuiTableColumnFlags_WidthFixed, 44);
                ImGui::TableHeadersRow();
                for (const auto& p : g.procs) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn(); ImGui::Text("%u", p.pid);
                    ImGui::TableNextColumn();
                    if (p.ai_hint) {
                        ImU32 col = accent_u32();
                        ImGui::PushStyleColor(ImGuiCol_Text, col);
                        ImGui::TextUnformatted(p.name.c_str());
                        ImGui::PopStyleColor();
                    } else {
                        ImGui::TextUnformatted(p.name.c_str());
                    }
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(fmt_bytes((double)p.vram_bytes).c_str());
                    ImGui::TableNextColumn(); ImGui::Text("%u", p.sm);
                    ImGui::TableNextColumn(); ImGui::Text("%u", p.mem);
                    ImGui::TableNextColumn(); ImGui::Text("%u", p.enc);
                    ImGui::TableNextColumn(); ImGui::Text("%u", p.dec);
                }
                ImGui::EndTable();
            }
        }
        ImGui::End();

        // ================= NETWORK =================
        ImGui::SetNextWindowPos({860, 30}, ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize({520, 850}, ImGuiCond_FirstUseEver);
        ImGui::Begin("Network");
        if (!capture) {
            ImGui::TextDisabled("capture disabled (--no-capture)");
        } else if (!net_ok) {
            ImGui::TextColored({1, 0.5f, 0.4f, 1}, "capture inactive");
            ImGui::TextWrapped("%s", net.error().c_str());
            if (!have_net_raw())
                ImGui::TextWrapped(
                    "grant CAP_NET_RAW: sudo setcap "
                    "'cap_net_raw,cap_net_admin+ep' ./build/drakon");
        } else {
            ImGui::Text("device  %s", net.device().c_str());
            ImGui::SameLine();
            ImGui::Checkbox("pause list", &pause_display);
            ImGui::SameLine();
            if (ImGui::Button("clear")) pkts.clear();

            ImGui::Text("in  %s/s", fmt_bytes(in_rate).c_str());
            ImGui::SameLine(180);
            ImGui::Text("out %s/s", fmt_bytes(out_rate).c_str());
            ImGui::Text("pkts %llu", (unsigned long long)net.total_pkts());
            ImGui::SameLine(180);
            ImGui::Text("total %s", fmt_bytes((double)net.total_bytes()).c_str());
            ImGui::TextDisabled("dropped ring %llu / kernel %llu",
                                (unsigned long long)net.ring_dropped(),
                                (unsigned long long)net.kernel_dropped());

            if (ImPlot::BeginPlot("##bw", ImVec2(-1, 110),
                                  ImPlotFlags_NoMenus | ImPlotFlags_NoBoxSelect)) {
                ImPlot::SetupAxes(nullptr, "KB/s", ImPlotAxisFlags_NoTickLabels,
                                  ImPlotAxisFlags_AutoFit);
                ImPlot::SetupAxisLimits(ImAxis_X1, now - 60, now, ImGuiCond_Always);
                if (r_in.count() > 1)
                    ImPlot::PlotLine("in", r_in.t.data(), r_in.v.data(),
                                     r_in.count(), 0, r_in.offset(), sizeof(float));
                if (r_out.count() > 1)
                    ImPlot::PlotLine("out", r_out.t.data(), r_out.v.data(),
                                     r_out.count(), 0, r_out.offset(), sizeof(float));
                ImPlot::EndPlot();
            }

            if (ImGui::BeginTabBar("nettabs")) {
                // ---- live packets ----
                if (ImGui::BeginTabItem("Packets")) {
                    ImGui::SetNextItemWidth(-1);
                    ImGui::InputTextWithHint("##pf", "filter text (addr / proto / L7)",
                                             pkt_filter, sizeof(pkt_filter));
                    const std::string needle = pkt_filter;

                    const ImGuiTableFlags tf = ImGuiTableFlags_RowBg |
                        ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY |
                        ImGuiTableFlags_SizingStretchProp;
                    if (ImGui::BeginTable("pk", 6, tf, ImVec2(0, 360))) {
                        ImGui::TableSetupScrollFreeze(0, 1);
                        ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 70);
                        ImGui::TableSetupColumn("Source");
                        ImGui::TableSetupColumn("Destination");
                        ImGui::TableSetupColumn("Proto", ImGuiTableColumnFlags_WidthFixed, 54);
                        ImGui::TableSetupColumn("Len", ImGuiTableColumnFlags_WidthFixed, 52);
                        ImGui::TableSetupColumn("Info");
                        ImGui::TableHeadersRow();

                        // newest first
                        for (auto it = pkts.rbegin(); it != pkts.rend(); ++it) {
                            const PacketRecord& p = *it;
                            std::string src = fmt_addr(p.family, p.saddr, p.sport);
                            std::string dst = fmt_addr(p.family, p.daddr, p.dport);
                            std::string info = l7_name(p.l7);
                            std::string fl = tcp_flags_str(p.tcp_flags);
                            if (!fl.empty()) info += (info.empty() ? "" : " ") + fl;

                            if (!needle.empty()) {
                                std::string hay = src + " " + dst + " " +
                                                  proto_name(p.l4) + " " + info;
                                if (hay.find(needle) == std::string::npos) continue;
                            }

                            ImGui::TableNextRow();
                            ImGui::TableNextColumn();
                            ImGui::TextDisabled("%.2f", p.ts - app_epoch);
                            ImGui::TableNextColumn(); ImGui::TextUnformatted(src.c_str());
                            ImGui::TableNextColumn(); ImGui::TextUnformatted(dst.c_str());
                            ImGui::TableNextColumn();
                            ImU32 pc = (p.l4 == IPPROTO_TCP)
                                           ? IM_COL32(120, 190, 255, 255)
                                           : (p.l4 == IPPROTO_UDP)
                                                 ? IM_COL32(160, 220, 150, 255)
                                                 : IM_COL32(200, 170, 120, 255);
                            ImGui::TextColored(ImColor(pc), "%s", proto_name(p.l4));
                            ImGui::TableNextColumn(); ImGui::Text("%u", p.length);
                            ImGui::TableNextColumn();
                            if (p.l7 == L7_OLLAMA || p.l7 == L7_LLM_API)
                                ImGui::TextColored(ImColor(accent_u32()), "%s", info.c_str());
                            else
                                ImGui::TextUnformatted(info.c_str());
                        }
                        ImGui::EndTable();
                    }
                    ImGui::EndTabItem();
                }

                // ---- flows / top talkers ----
                if (ImGui::BeginTabItem("Flows")) {
                    auto flows = net.flows_snapshot();
                    std::sort(flows.begin(), flows.end(),
                              [](const FlowStat& a, const FlowStat& b) {
                                  return (a.bytes_ab + a.bytes_ba) >
                                         (b.bytes_ab + b.bytes_ba);
                              });
                    const ImGuiTableFlags tf = ImGuiTableFlags_RowBg |
                        ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY |
                        ImGuiTableFlags_SizingStretchProp;
                    if (ImGui::BeginTable("fl", 6, tf, ImVec2(0, 360))) {
                        ImGui::TableSetupScrollFreeze(0, 1);
                        ImGui::TableSetupColumn("Proto", ImGuiTableColumnFlags_WidthFixed, 54);
                        ImGui::TableSetupColumn("Endpoint A");
                        ImGui::TableSetupColumn("Endpoint B");
                        ImGui::TableSetupColumn("L7", ImGuiTableColumnFlags_WidthFixed, 64);
                        ImGui::TableSetupColumn("Pkts", ImGuiTableColumnFlags_WidthFixed, 64);
                        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 80);
                        ImGui::TableHeadersRow();
                        int shown = 0;
                        for (const auto& f : flows) {
                            if (f.family == 0) continue;
                            if (++shown > 300) break;
                            ImGui::TableNextRow();
                            ImGui::TableNextColumn();
                            ImGui::TextUnformatted(proto_name(f.l4));
                            ImGui::TableNextColumn();
                            ImGui::TextUnformatted(
                                fmt_addr(f.family, f.a_addr, f.a_port).c_str());
                            ImGui::TableNextColumn();
                            ImGui::TextUnformatted(
                                fmt_addr(f.family, f.b_addr, f.b_port).c_str());
                            ImGui::TableNextColumn();
                            ImGui::TextUnformatted(l7_name(f.l7));
                            ImGui::TableNextColumn();
                            ImGui::Text("%llu",
                                        (unsigned long long)(f.pkts_ab + f.pkts_ba));
                            ImGui::TableNextColumn();
                            ImGui::TextUnformatted(
                                fmt_bytes((double)(f.bytes_ab + f.bytes_ba)).c_str());
                        }
                        ImGui::EndTable();
                    }
                    ImGui::EndTabItem();
                }
                ImGui::EndTabBar();
            }
        }
        ImGui::End();

        // ---- render ------------------------------------------------------
        ImGui::Render();
        int fbw, fbh;
        glfwGetFramebufferSize(win, &fbw, &fbh);
        glViewport(0, 0, fbw, fbh);
        glClearColor(0.05f, 0.055f, 0.065f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(win);

        frame_cycles = rdtsc_serialised() - c_begin;
    }

    net.stop();
    gpu.stop();
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImPlot::DestroyContext();
    ImGui::DestroyContext();
    glfwDestroyWindow(win);
    glfwTerminate();
    return 0;
}
