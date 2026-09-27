cmake_minimum_required(VERSION 3.20)
project(drakon LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()

option(DRAKON_SANITIZE "Build with ASan+UBSan (implies Debug)" OFF)

include(FetchContent)

# ---- Dear ImGui (docking) + ImPlot -----------------------------------------
# Pinned to a known-compatible pair. Bump both together if you upgrade.
FetchContent_Declare(imgui
  GIT_REPOSITORY https://github.com/ocornut/imgui.git
  GIT_TAG        v1.90.9-docking)
FetchContent_Declare(implot
  GIT_REPOSITORY https://github.com/epezent/implot.git
  GIT_TAG        v0.16)
FetchContent_MakeAvailable(imgui implot)

# ---- system dependencies ----------------------------------------------------
find_package(OpenGL REQUIRED)
find_package(glfw3 REQUIRED)

find_library(PCAP_LIB pcap REQUIRED)
find_path(PCAP_INC pcap/pcap.h REQUIRED)

find_library(CAP_LIB cap REQUIRED)
find_path(CAP_INC sys/capability.h REQUIRED)

# NVML ships its header with the CUDA toolkit and its runtime library with the
# driver. Search the usual locations; override with -DNVML_INCLUDE_DIR=... and
# -DNVML_LIBRARY=... if they live somewhere unusual.
find_path(NVML_INCLUDE_DIR nvml.h
  HINTS /usr/local/cuda/include /usr/include /opt/cuda/include
        /usr/local/cuda/targets/x86_64-linux/include)
find_library(NVML_LIBRARY
  NAMES nvidia-ml
  HINTS /usr/lib/x86_64-linux-gnu /usr/lib
        /usr/local/cuda/targets/x86_64-linux/lib/stubs)
if(NOT NVML_INCLUDE_DIR OR NOT NVML_LIBRARY)
  message(FATAL_ERROR
    "NVML not found. Install the CUDA toolkit for nvml.h, or set "
    "-DNVML_INCLUDE_DIR and -DNVML_LIBRARY. Header searched: ${NVML_INCLUDE_DIR}, "
    "library: ${NVML_LIBRARY}")
endif()

# ---- third-party UI object library (kept out of our warning surface) --------
add_library(imgui_impl STATIC
  ${imgui_SOURCE_DIR}/imgui.cpp
  ${imgui_SOURCE_DIR}/imgui_draw.cpp
  ${imgui_SOURCE_DIR}/imgui_tables.cpp
  ${imgui_SOURCE_DIR}/imgui_widgets.cpp
  ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
  ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
  ${implot_SOURCE_DIR}/implot.cpp
  ${implot_SOURCE_DIR}/implot_items.cpp)
target_include_directories(imgui_impl PUBLIC
  ${imgui_SOURCE_DIR} ${imgui_SOURCE_DIR}/backends ${implot_SOURCE_DIR})
target_link_libraries(imgui_impl PUBLIC glfw OpenGL::GL)

# ---- application ------------------------------------------------------------
add_executable(drakon
  src/main.cpp
  src/gpu.cpp
  src/net.cpp
  src/sysstat.cpp
  src/privilege.cpp
  src/theme.cpp)

target_include_directories(drakon PRIVATE
  ${PCAP_INC} ${CAP_INC} ${NVML_INCLUDE_DIR})
target_link_libraries(drakon PRIVATE
  imgui_impl ${PCAP_LIB} ${CAP_LIB} ${NVML_LIBRARY} dl pthread)

target_compile_options(drakon PRIVATE -Wall -Wextra -Wformat -Wformat-security)

if(DRAKON_SANITIZE)
  target_compile_options(drakon PRIVATE
    -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined)
  target_link_options(drakon PRIVATE -fsanitize=address,undefined)
else()
  # Hardened release posture.
  target_compile_options(drakon PRIVATE
    -fstack-protector-strong -fstack-clash-protection
    -D_FORTIFY_SOURCE=3)
  target_link_options(drakon PRIVATE
    -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
endif()
