#include "sysstat.hpp"

#include <unistd.h>

#include <cstdio>
#include <cstring>

SysSample Sysstat::sample() {
    SysSample s;
    s.cores = static_cast<unsigned>(sysconf(_SC_NPROCESSORS_ONLN));

    // CPU: aggregate line of /proc/stat. Busy = total - (idle + iowait).
    if (FILE* f = std::fopen("/proc/stat", "re")) {
        unsigned long long user, nice, sys, idle, iowait, irq, softirq, steal;
        user = nice = sys = idle = iowait = irq = softirq = steal = 0;
        if (std::fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu", &user,
                        &nice, &sys, &idle, &iowait, &irq, &softirq, &steal) >= 4) {
            const unsigned long long idle_all = idle + iowait;
            const unsigned long long total =
                user + nice + sys + idle + iowait + irq + softirq + steal;
            if (primed_) {
                const unsigned long long dt = total - prev_total_;
                const unsigned long long di = idle_all - prev_idle_;
                if (dt > 0) s.cpu_pct = 100.0 * (double)(dt - di) / (double)dt;
            }
            prev_total_ = total;
            prev_idle_ = idle_all;
            primed_ = true;
        }
        std::fclose(f);
    }

    // Memory: MemTotal and MemAvailable from /proc/meminfo.
    if (FILE* f = std::fopen("/proc/meminfo", "re")) {
        char key[64];
        unsigned long long val;
        char unit[16];
        unsigned long long total = 0, avail = 0;
        while (std::fscanf(f, "%63s %llu %15s", key, &val, unit) == 3) {
            if (std::strcmp(key, "MemTotal:") == 0) total = val;
            else if (std::strcmp(key, "MemAvailable:") == 0) avail = val;
            if (total && avail) break;
        }
        s.mem_total_kb = total;
        s.mem_used_kb = (total > avail) ? total - avail : 0;
        std::fclose(f);
    }

    if (FILE* f = std::fopen("/proc/loadavg", "re")) {
        if (std::fscanf(f, "%lf", &s.load1) != 1) s.load1 = 0.0;
        std::fclose(f);
    }
    return s;
}
