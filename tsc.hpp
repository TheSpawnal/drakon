#pragma once
#include <cstdint>
#include <chrono>

// High-resolution cycle counter via the x86 time-stamp counter.
//
// rdtscp serialises against all prior instructions (unlike bare rdtsc, which
// the CPU may reorder) and returns the core id in ECX, discarded here. The
// trailing lfence stops later instructions from being hoisted above the read,
// so the value brackets exactly the region we intend to measure. On every
// modern part the TSC is invariant (constant rate regardless of P-state), so a
// single calibration against the wall clock holds for the process lifetime.
#if defined(__x86_64__) || defined(__i386__)
static inline uint64_t rdtsc_serialised() {
    uint32_t lo, hi, aux;
    __asm__ __volatile__("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux));
    __asm__ __volatile__("lfence" ::: "memory");
    return (static_cast<uint64_t>(hi) << 32) | lo;
}
#else
static inline uint64_t rdtsc_serialised() {
    return static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
}
#endif

// One-shot estimate of the counter's tick rate in Hz, measured against a known
// wall-clock interval. Used only to render the per-frame cost in real cycles.
inline double estimate_tsc_hz() {
    using namespace std::chrono;
    const uint64_t c0 = rdtsc_serialised();
    const auto t0 = steady_clock::now();
    while (steady_clock::now() - t0 < milliseconds(50)) { /* settle */ }
    const uint64_t c1 = rdtsc_serialised();
    const auto t1 = steady_clock::now();
    const double secs = duration<double>(t1 - t0).count();
    return secs > 0.0 ? static_cast<double>(c1 - c0) / secs : 0.0;
}
