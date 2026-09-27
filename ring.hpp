#pragma once
#include <atomic>
#include <cstddef>
#include <cstdint>

// Single-producer / single-consumer bounded ring.
// Producer is the capture thread, consumer is the UI thread. On overflow the
// producer drops the incoming item and bumps a counter rather than blocking,
// so a stalled UI can never back-pressure or stall packet capture.
template <typename T, size_t N>
class SpscRing {
    static_assert((N & (N - 1)) == 0, "N must be a power of two");

public:
    bool push(const T& v) {
        const size_t h = head_.load(std::memory_order_relaxed);
        const size_t next = (h + 1) & (N - 1);
        if (next == tail_.load(std::memory_order_acquire)) {
            dropped_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        buf_[h] = v;
        head_.store(next, std::memory_order_release);
        return true;
    }

    bool pop(T& out) {
        const size_t t = tail_.load(std::memory_order_relaxed);
        if (t == head_.load(std::memory_order_acquire)) return false;
        out = buf_[t];
        tail_.store((t + 1) & (N - 1), std::memory_order_release);
        return true;
    }

    uint64_t dropped() const { return dropped_.load(std::memory_order_relaxed); }

private:
    T buf_[N];
    std::atomic<size_t> head_{0};
    std::atomic<size_t> tail_{0};
    std::atomic<uint64_t> dropped_{0};
};
