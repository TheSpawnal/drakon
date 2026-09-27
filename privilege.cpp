#include "privilege.hpp"
#include <sys/capability.h>

bool drop_all_capabilities() {
    cap_t empty = cap_init();  // a fresh cap set with every flag cleared
    if (!empty) return false;
    const bool ok = (cap_set_proc(empty) == 0);
    cap_free(empty);
    return ok;
}

bool have_net_raw() {
    cap_t cur = cap_get_proc();
    if (!cur) return false;
    cap_flag_value_t v = CAP_CLEAR;
    cap_get_flag(cur, CAP_NET_RAW, CAP_EFFECTIVE, &v);
    cap_free(cur);
    return v == CAP_SET;
}
