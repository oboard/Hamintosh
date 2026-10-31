#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BINARY="${CA_RENDERER_BINARY:-/tmp/harmonios-ca-metal2vulkan}"
CACHE="${CA_RENDERER_CACHE:-/tmp/harmonios-mac-cache}"
ICD="${MOLTENVK_ICD:-/opt/homebrew/etc/vulkan/icd.d/MoltenVK_icd.json}"

cd "$ROOT"
cargo build --manifest-path runtime/Cargo.toml --lib
xcrun clang++ -std=c++17 -Wall -Wextra -Werror -Wno-unused-function \
  native/graphics/ca_renderer_probe.cpp tests/ca_renderer_mac_host.cpp \
  runtime/target/debug/libharmonios_runtime.a \
  -framework Foundation -framework Metal -framework QuartzCore -framework CoreGraphics \
  -ldl -lpthread -o "$BINARY"
mkdir -p "$CACHE"
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
export XDG_CACHE_HOME="$CACHE"
export VK_ICD_FILENAMES="$ICD"
exec "$BINARY" "$@"
