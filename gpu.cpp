#include "gpu.hpp"

#include <nvml.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>

namespace {

nvmlDevice_t as_dev(void* p) { return reinterpret_cast<nvmlDevice_t>(p); }

// Stable ABI bit values for clock-throttle reasons. Hardcoded rather than
// referencing the NVML macros because those were renamed (ClocksThrottleReason
// -> ClocksEventReason) across header versions while the bit values did not
// change. This keeps the decoder compiling on any recent driver.
struct ThrottleBit { unsigned long long bit; const char* label; };
constexpr ThrottleBit kThrottle[] = {
    {0x0000000000000001ULL, "GPU idle"},
    {0x0000000000000002ULL, "App clock setting"},
    {0x0000000000000004ULL, "SW power cap"},
    {0x0000000000000008ULL, "HW slowdown"},
    {0x0000000000000010ULL, "Sync boost"},
    {0x0000000000000020ULL, "SW thermal"},
    {0x0000000000000040ULL, "HW thermal"},
    {0x0000000000000080ULL, "HW power brake"},
    {0x0000000000000100ULL, "Display clock"},
};

std::string comm_of(uint32_t pid) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%u/comm", pid);
    FILE* f = std::fopen(path, "re");
    if (!f) return {};
    char buf[128] = {0};
    const size_t n = std::fread(buf, 1, sizeof(buf) - 1, f);
    std::fclose(f);
    std::string s(buf, n);
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}

bool looks_like_ai(const std::string& name) {
    static const char* kNeedles[] = {
        "python", "ollama", "llama", "vllm", "gemma", "kobold", "llamafile",
        "tgi", "sglang", "exllama", "mlc", "ggml", "triton", "comfy", "koboldcpp"};
    std::string low = name;
    std::transform(low.begin(), low.end(), low.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    for (const char* n : kNeedles)
        if (low.find(n) != std::string::npos) return true;
    return false;
}

}  // namespace

std::vector<std::pair<unsigned long long, const char*>>
decode_throttle(unsigned long long bits) {
    std::vector<std::pair<unsigned long long, const char*>> out;
    for (const auto& t : kThrottle)
        if (bits & t.bit) out.emplace_back(t.bit, t.label);
    return out;
}

GpuMonitor::~GpuMonitor() { stop(); }

bool GpuMonitor::start(unsigned interval_ms) {
    if (nvmlInit_v2() != NVML_SUCCESS) {
        error_ = "nvmlInit failed (driver or library not present)";
        return false;
    }
    unsigned count = 0;
    if (nvmlDeviceGetCount_v2(&count) != NVML_SUCCESS || count == 0) {
        error_ = "no NVML devices found";
        nvmlShutdown();
        return false;
    }
    nvmlDevice_t dev{};
    if (nvmlDeviceGetHandleByIndex_v2(0, &dev) != NVML_SUCCESS) {
        error_ = "could not obtain device handle";
        nvmlShutdown();
        return false;
    }
    dev_ = reinterpret_cast<void*>(dev);
    available_ = true;
    run_ = true;
    th_ = std::thread(&GpuMonitor::loop, this, interval_ms);
    return true;
}

void GpuMonitor::stop() {
    if (run_.exchange(false)) {
        if (th_.joinable()) th_.join();
        nvmlShutdown();
        available_ = false;
    }
}

void GpuMonitor::loop(unsigned interval_ms) {
    nvmlDevice_t dev = as_dev(dev_);

    {
        char name[NVML_DEVICE_NAME_BUFFER_SIZE] = {0};
        if (nvmlDeviceGetName(dev, name, sizeof(name)) == NVML_SUCCESS) {
            std::lock_guard<std::mutex> lk(mtx_);
            latest_.name = name;
        }
    }

    while (run_.load()) {
        GpuSample s;
        s.name = latest_.name;
        s.valid = true;

        nvmlUtilization_t u{};
        if (nvmlDeviceGetUtilizationRates(dev, &u) == NVML_SUCCESS) {
            s.util_gpu = u.gpu;
            s.util_mem = u.memory;
        }

        nvmlMemory_t m{};
        if (nvmlDeviceGetMemoryInfo(dev, &m) == NVML_SUCCESS) {
            s.mem_used = m.used;
            s.mem_total = m.total;
        }

        unsigned t = 0;
        if (nvmlDeviceGetTemperature(dev, NVML_TEMPERATURE_GPU, &t) == NVML_SUCCESS)
            s.temp_c = t;

        unsigned p = 0;
        if (nvmlDeviceGetPowerUsage(dev, &p) == NVML_SUCCESS) s.power_mw = p;
        unsigned pl = 0;
        if (nvmlDeviceGetEnforcedPowerLimit(dev, &pl) == NVML_SUCCESS)
            s.power_limit_mw = pl;

        unsigned c = 0;
        if (nvmlDeviceGetClockInfo(dev, NVML_CLOCK_SM, &c) == NVML_SUCCESS)
            s.clock_sm_mhz = c;
        if (nvmlDeviceGetClockInfo(dev, NVML_CLOCK_MEM, &c) == NVML_SUCCESS)
            s.clock_mem_mhz = c;

        unsigned fan = 0;
        if (nvmlDeviceGetFanSpeed(dev, &fan) == NVML_SUCCESS) s.fan_pct = fan;

        unsigned tx = 0, rx = 0;
        if (nvmlDeviceGetPcieThroughput(dev, NVML_PCIE_UTIL_TX_BYTES, &tx) == NVML_SUCCESS)
            s.pcie_tx_kbs = tx;
        if (nvmlDeviceGetPcieThroughput(dev, NVML_PCIE_UTIL_RX_BYTES, &rx) == NVML_SUCCESS)
            s.pcie_rx_kbs = rx;

        unsigned eu = 0, du = 0, period = 0;
        if (nvmlDeviceGetEncoderUtilization(dev, &eu, &period) == NVML_SUCCESS)
            s.enc_util = eu;
        if (nvmlDeviceGetDecoderUtilization(dev, &du, &period) == NVML_SUCCESS)
            s.dec_util = du;

        unsigned long long thr = 0;
        if (nvmlDeviceGetCurrentClocksThrottleReasons(dev, &thr) == NVML_SUCCESS)
            s.throttle_bits = thr;

        // Per-process VRAM: merge compute and graphics contexts, keeping the
        // largest resident footprint seen for each PID.
        auto collect = [&](nvmlReturn_t (*fn)(nvmlDevice_t, unsigned int*,
                                              nvmlProcessInfo_t*)) {
            unsigned int n = 0;
            nvmlReturn_t r = fn(dev, &n, nullptr);
            if (r != NVML_ERROR_INSUFFICIENT_SIZE || n == 0) return;
            std::vector<nvmlProcessInfo_t> infos(n);
            if (fn(dev, &n, infos.data()) != NVML_SUCCESS) return;
            for (unsigned i = 0; i < n; ++i) {
                unsigned long long vram = infos[i].usedGpuMemory;
                if (vram == static_cast<unsigned long long>(-1)) vram = 0;
                auto it = std::find_if(s.procs.begin(), s.procs.end(),
                    [&](const GpuProc& gp) { return gp.pid == infos[i].pid; });
                if (it == s.procs.end()) {
                    GpuProc gp;
                    gp.pid = infos[i].pid;
                    gp.name = comm_of(gp.pid);
                    gp.ai_hint = looks_like_ai(gp.name);
                    gp.vram_bytes = vram;
                    s.procs.push_back(std::move(gp));
                } else if (vram > it->vram_bytes) {
                    it->vram_bytes = vram;
                }
            }
        };
        collect(nvmlDeviceGetComputeRunningProcesses);
        collect(nvmlDeviceGetGraphicsRunningProcesses);

        // Per-process compute utilisation since the last sample.
        {
            unsigned int n = 0;
            nvmlReturn_t r = nvmlDeviceGetProcessUtilization(dev, nullptr, &n,
                                                             last_util_ts_);
            if (r == NVML_ERROR_INSUFFICIENT_SIZE && n > 0) {
                std::vector<nvmlProcessUtilizationSample_t> us(n);
                if (nvmlDeviceGetProcessUtilization(dev, us.data(), &n,
                                                    last_util_ts_) == NVML_SUCCESS) {
                    for (unsigned i = 0; i < n; ++i) {
                        last_util_ts_ = std::max(last_util_ts_, us[i].timeStamp);
                        auto it = std::find_if(s.procs.begin(), s.procs.end(),
                            [&](const GpuProc& gp) { return gp.pid == us[i].pid; });
                        if (it == s.procs.end()) {
                            GpuProc gp;
                            gp.pid = us[i].pid;
                            gp.name = comm_of(gp.pid);
                            gp.ai_hint = looks_like_ai(gp.name);
                            it = s.procs.insert(s.procs.end(), std::move(gp));
                        }
                        it->sm = us[i].smUtil;
                        it->mem = us[i].memUtil;
                        it->enc = us[i].encUtil;
                        it->dec = us[i].decUtil;
                    }
                }
            }
        }

        std::sort(s.procs.begin(), s.procs.end(),
                  [](const GpuProc& a, const GpuProc& b) {
                      return a.vram_bytes > b.vram_bytes;
                  });

        {
            std::lock_guard<std::mutex> lk(mtx_);
            latest_ = std::move(s);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }
}

GpuSample GpuMonitor::snapshot() {
    std::lock_guard<std::mutex> lk(mtx_);
    return latest_;
}
