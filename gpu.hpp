#pragma once
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

// One process holding GPU resources. The per-process utilisation fields
// (sm/mem/enc/dec) are the AI-workflow signal: they show which PID is actually
// driving the tensor cores versus merely holding VRAM.
struct GpuProc {
    uint32_t pid = 0;
    std::string name;                     // /proc/<pid>/comm
    unsigned long long vram_bytes = 0;    // resident GPU memory
    unsigned sm = 0, mem = 0, enc = 0, dec = 0;  // % over last interval
    bool ai_hint = false;                 // name matches a known inference runtime
};

// A full device reading. `valid` is false when a metric could not be taken;
// individual fields left at 0 mean "unsupported on this device" rather than
// "measured zero", and the UI renders them accordingly.
struct GpuSample {
    bool valid = false;
    std::string name;
    unsigned util_gpu = 0, util_mem = 0;             // %
    unsigned long long mem_used = 0, mem_total = 0;  // bytes
    unsigned temp_c = 0;
    unsigned power_mw = 0, power_limit_mw = 0;
    unsigned clock_sm_mhz = 0, clock_mem_mhz = 0;
    unsigned fan_pct = 0;
    unsigned pcie_tx_kbs = 0, pcie_rx_kbs = 0;       // KB/s over PCIe
    unsigned enc_util = 0, dec_util = 0;             // % NVENC / NVDEC
    unsigned long long throttle_bits = 0;            // clock-limiting reasons
    std::vector<GpuProc> procs;
};

class GpuMonitor {
public:
    ~GpuMonitor();
    bool start(unsigned interval_ms = 500);
    void stop();
    GpuSample snapshot();  // thread-safe copy of the most recent reading
    bool available() const { return available_; }
    const std::string& error() const { return error_; }

private:
    void loop(unsigned interval_ms);

    std::thread th_;
    std::atomic<bool> run_{false};
    std::mutex mtx_;
    GpuSample latest_;
    bool available_ = false;
    std::string error_;
    void* dev_ = nullptr;              // nvmlDevice_t, kept opaque in the header
    unsigned long long last_util_ts_ = 0;
};

// Decode a clock-throttle bitmask into a list of (bit, short label) pairs for
// the active reasons only.
std::vector<std::pair<unsigned long long, const char*>>
decode_throttle(unsigned long long bits);
