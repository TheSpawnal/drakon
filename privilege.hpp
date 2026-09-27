#pragma once

// Drop every POSIX capability from the process (permitted, effective and
// inheritable sets all cleared). Called immediately after the capture socket
// is opened, so the elevated rights granted by file capabilities exist for a
// single syscall window and nothing more. Returns true on success.
bool drop_all_capabilities();

// Reports whether CAP_NET_RAW is currently in the effective set. Purely
// informational, used to render an accurate hint in the UI.
bool have_net_raw();
