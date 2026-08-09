#!/usr/bin/env bash
# build.sh — builds the dumper for every supported target.
#
#   ./build.sh           # build all (native linux .so + windows dll via mingw)
#   ./build.sh linux     # native linux only
#   ./build.sh windows   # windows dll (mingw cross-compile) only
#
set -euo pipefail
cd "$(dirname "$0")"

target="${1:-all}"

build_linux() {
    echo "==> Building native Linux dumper (libIl2cppDumperR.so)"
    cmake -B build/linux -DCMAKE_BUILD_TYPE=Release
    cmake --build build/linux -j"$(nproc)"
    echo "    -> build/linux/libIl2cppDumperR.so"
}

build_windows() {
    echo "==> Building Windows dumper via MinGW (Il2cppDumperR.dll)"
    cmake -B build/mingw -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64-x86_64.cmake -DCMAKE_BUILD_TYPE=Release
    cmake --build build/mingw -j"$(nproc)"
    echo "    -> build/mingw/Il2cppDumperR.dll"
}

case "$target" in
    linux)   build_linux ;;
    windows) build_windows ;;
    all)     build_linux; build_windows ;;
    *) echo "usage: $0 [linux|windows|all]"; exit 1 ;;
esac
