#!/usr/bin/env bash
# Install build and runtime dependencies for drakon on Ubuntu.
set -euo pipefail

sudo apt update
sudo apt install -y \
  build-essential cmake ninja-build pkg-config git \
  libglfw3-dev libgl1-mesa-dev \
  libpcap-dev libcap-dev

echo
echo "NVML: nvml.h ships with the CUDA toolkit; the runtime library"
echo "(libnvidia-ml.so) comes with the NVIDIA driver you already run."
echo "If the build reports NVML not found, install the toolkit headers:"
echo "  sudo apt install -y nvidia-cuda-toolkit"
echo "or pass -DNVML_INCLUDE_DIR=/path/to/include to cmake."
