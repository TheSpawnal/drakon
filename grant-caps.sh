#!/usr/bin/env bash
# Grant the packet-capture capabilities to the built binary as file
# capabilities, so drakon runs as your normal user, not root. The process
# sheds these the instant the capture socket is open (see net.cpp).
set -euo pipefail

BIN="${1:-build/drakon}"
if [[ ! -x "$BIN" ]]; then
  echo "binary not found: $BIN" >&2
  echo "usage: $0 [path-to-drakon]" >&2
  exit 1
fi

sudo setcap 'cap_net_raw,cap_net_admin+ep' "$BIN"
echo "granted:"
getcap "$BIN"
