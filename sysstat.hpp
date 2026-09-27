#pragma once
#include <cstdint>

// Lightweight host context sampled from /proc. Relevant to AI monitoring
// because CPU-offloaded layers and KV-cache paging show up here, not on the
// GPU. Sampling is cheap and non-blocking, so it runs inline on the UI thread.
struct SysSample {
    double cpu_pct = 0.0;              // aggregate busy fraction since last call
    unsigned cores = 0;
    unsigned long long mem_used_kb = 0, mem_total_kb = 0;
    double load1 = 0.0;
};

class Sysstat {
public:
    SysSample sample();               // stateful: computes CPU delta vs prev call

private:
    unsigned long long prev_total_ = 0, prev_idle_ = 0;
    bool primed_ = false;
};
