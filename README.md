# drakon
sometimes your local llm can act like a silly wh0re;
A native GPU/AI telemetry cockpit fused with a live packet sniffer, in one
window. Built for a workstation that hosts local models: it shows which process
is driving the GPU and burning VRAM, whether the card is throttling, and what
that model server and its agents are talking to on the network.

Written in C++17 with a small amount of x86 inline assembly. GPU metrics come
from NVML (the library `nvidia-smi` speaks). Packet capture uses libpcap, the
same foundation as tcpdump and Wireshark. UI is Dear ImGui + ImPlot on GLFW.

## What it shows

GPU: device utilisation, VRAM used/total, temperature, power draw against the
enforced limit, SM and memory clocks, fan, PCIe throughput, NVENC/NVDEC use,
and active clock-throttle reasons. Rolling plots for utilisation, VRAM, power
and temperature.

Per-process GPU: every PID holding GPU memory, its resident VRAM, and its
compute/memory/encoder/decoder utilisation over the last interval. Names that
match a known inference runtime (python, ollama, llama, vllm, gemma, and
others) are highlighted. This is the panel that answers "what is my model
actually costing right now".

System: aggregate CPU, RAM, one-minute load, UI frame rate, and the measured
per-frame cost in real CPU cycles via the time-stamp counter.

Network: in/out byte rate with a bandwidth plot, total packet and byte
counters, and drop counters for both the internal ring and the kernel. A live
packet list (time, source, destination, protocol, length, and an L7 hint plus
TCP flags), and a flows view aggregating bidirectional conversations into top
talkers.

## Security model

The tool is built around privilege minimisation and a refusal to store payload.

- Capabilities, not root. Packet capture needs `CAP_NET_RAW` (and
  `CAP_NET_ADMIN` for promiscuous mode). These are granted as file
  capabilities on the binary, so the process runs as your user. The moment the
  capture handle is activated, the process drops every capability
  (`cap_set_proc` on an empty set) before a single packet byte is parsed. The
  elevated window is one syscall wide.
- Header-only capture. The snap length is clamped to 96-262 bytes (default
  128), enough for L2-L4 headers and nothing more. Payloads are never copied
  into memory and never written to disk.
- Promiscuous mode is off by default, so only traffic the host would normally
  see is captured. A BPF filter (default `ip or ip6`) narrows scope further.
- The dissector is the attack surface. Every field read goes through a cursor
  that checks bounds against the captured length first; the IPv6 extension
  chain is walked with a hard depth cap. This is deliberate: historically most
  packet-analyser vulnerabilities are dissector overreads on malformed input.
- Hardened build: stack protector, stack-clash protection, `_FORTIFY_SOURCE=3`,
  full RELRO, non-executable stack, PIE. A sanitizer build is one flag away.

Capture opens once at startup and then privileges are dropped, so changing the
capture device or filter means relaunching. That is the intended trade-off:
drop early, stay dropped.

## Build

```
./scripts/setup-deps.sh
cmake -S . -B build -G Ninja
cmake --build build
```

The first configure fetches Dear ImGui and ImPlot (pinned versions) over the
network. Everything else is a system package.

## Run

GPU and system panels need no privileges:

```
./build/drakon --no-capture
```

For packet capture, grant the capabilities once, then run:

```
./scripts/grant-caps.sh build/drakon
./build/drakon
```

Default device is `any`, which includes loopback, so a model server on
`127.0.0.1:11434` and its agent traffic are visible without extra setup.

### Options

```
--device NAME    capture device (default: any)
--filter BPF     capture filter (default: "ip or ip6")
--snaplen N      header bytes to capture, clamped 96-262 (default: 128)
--promisc        enable promiscuous mode (off by default)
--no-capture     GPU/system only; needs no capabilities
```

### Controls

Panels are dockable and resizable; drag them into whatever layout you like. The
packet list has a text filter (matches address, protocol, or L7 hint), a pause
toggle, and a clear button. The bandwidth plot and rolling GPU plots cover a
sixty-second window.

Optional fonts: drop `Inter-Regular.ttf` and `JetBrainsMono-Regular.ttf` into
an `assets/` directory beside the binary to upgrade from the built-in font.

## Scope, honestly

This does L2-L4 dissection plus port-based L7 hints. It is not a Wireshark
replacement and does not decode application protocols. For deep dissection,
follow a conversation of interest in Wireshark or `tshark`; drakon is the
always-on cockpit that tells you when to go look.

## First-build notes

The GPU/GL/pcap stack cannot be exercised without the real driver and hardware,
so two spots may need a one-line adjustment on first build:

- NVML throttle symbol. `net`/`gpu.cpp` calls
  `nvmlDeviceGetCurrentClocksThrottleReasons`. Very recent headers rename this
  to `...ClocksEventReasons`. If the compiler cannot find the symbol, change
  that one call; the decoded bit values are already version-independent.
- NVML header path. If CMake cannot find `nvml.h`, install the CUDA toolkit or
  pass `-DNVML_INCLUDE_DIR=/path/to/include`. The runtime library is already
  present from the driver.

## Layout

```
src/
  main.cpp       UI, docking, panels, plots
  gpu.*          NVML device and per-process sampling (thread)
  net.*          libpcap capture, bounded dissector, flow table (thread)
  sysstat.*      /proc CPU/RAM/load (inline)
  privilege.*    capability dropping
  ring.hpp       SPSC lock-free ring for the packet fast-path
  tsc.hpp        x86 time-stamp counter (inline asm)
  theme.*        dark theme
scripts/
  setup-deps.sh  apt dependencies
  grant-caps.sh  file capabilities on the binary
```

## Ideas to extend

Per-process network attribution by correlating flows with `/proc/net` socket
inodes. GPU power/thermal alerting with a log. Export of the flow table to a
pcap-ng summary. A second NVML device loop for multi-GPU. A DLT_NFLOG path for
capturing from an nftables log group without raw sockets at all.
