#!/usr/bin/env bash
# build.sh — builds LineageHide and produces lineagehide.zip
#
# Requirements:
#   • Android NDK r25c+  (set NDK=/path/to/ndk or ANDROID_NDK_HOME)
#   • cmake, ninja (usually bundled with NDK)
#   • Python 3.6+ (for gen_dex.py)
#   • git submodules initialised:
#       git submodule update --init --recursive
#
# Usage:
#   ./build.sh [Debug|Release]   (default: Release)

set -euo pipefail

BUILD_TYPE="${1:-Release}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NDK="${NDK:-${ANDROID_NDK_HOME:-}}"
OUT="$SCRIPT_DIR/out"
MODULE_STAGING="$SCRIPT_DIR/_staging"

# ── Locate NDK ────────────────────────────────────────────────────────────────
if [ -z "$NDK" ]; then
    # Try some common paths
    for candidate in \
        "$HOME/Android/Sdk/ndk/25.2.9519653" \
        "$HOME/Library/Android/sdk/ndk/25.2.9519653" \
        "/opt/android-ndk"; do
        if [ -d "$candidate" ]; then NDK="$candidate"; break; fi
    done
fi

if [ -z "$NDK" ] || [ ! -d "$NDK" ]; then
    echo "ERROR: Android NDK not found. Set NDK=/path/to/ndk or ANDROID_NDK_HOME."
    exit 1
fi

CMAKE="$NDK/build/cmake/android.toolchain.cmake"
if [ ! -f "$CMAKE" ]; then
    echo "ERROR: NDK toolchain not found at $CMAKE"
    exit 1
fi

echo "Using NDK: $NDK"

# ── Check submodules ──────────────────────────────────────────────────────────
# Each entry: <path that must exist once the submodule is initialised>
SUBMODULE_CHECKS=(
    "native/libs/dobby/CMakeLists.txt"
    "native/libs/lsplant/lsplant/src/main/jni/lsplant.cc"
    "native/libs/lsplant/lsplant/src/main/jni/external/dex_builder/CMakeLists.txt"
    "native/libs/zygisk/module/jni/zygisk.hpp"
)
for check in "${SUBMODULE_CHECKS[@]}"; do
    if [ ! -f "$SCRIPT_DIR/$check" ]; then
        echo "ERROR: submodule not initialised (missing: $check)."
        echo "Run: git submodule update --init --recursive"
        exit 1
    fi
done

# ── Generate hooks.dex ───────────────────────────────────────────────────────
echo "Generating hooks.dex..."
python3 "$SCRIPT_DIR/tools/gen_dex.py"

# ── Build native .so for each ABI ────────────────────────────────────────────
ABIS=("arm64-v8a" "armeabi-v7a" "x86_64" "x86")

for ABI in "${ABIS[@]}"; do
    echo "Building $ABI ($BUILD_TYPE)..."
    BUILD_DIR="$OUT/build-$ABI"
    mkdir -p "$BUILD_DIR"

    cmake -G Ninja \
        -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
        -DCMAKE_TOOLCHAIN_FILE="$CMAKE" \
        -DANDROID_ABI="$ABI" \
        -DANDROID_PLATFORM=android-29 \
        -DANDROID_STL=c++_static \
        -B "$BUILD_DIR" \
        -S "$SCRIPT_DIR/native"

    cmake --build "$BUILD_DIR" --parallel
done

# ── Stage the module ─────────────────────────────────────────────────────────
echo "Staging module..."
rm -rf "$MODULE_STAGING"
cp -r "$SCRIPT_DIR/module" "$MODULE_STAGING"

# Copy zygisk .so files
mkdir -p "$MODULE_STAGING/zygisk"
for ABI in "${ABIS[@]}"; do
    SO="$OUT/build-$ABI/zygisk/${ABI}.so"
    if [ -f "$SO" ]; then
        cp "$SO" "$MODULE_STAGING/zygisk/${ABI}.so"
        # Also copy a .so.debug (unstripped) if it exists, renamed
        echo "  + zygisk/${ABI}.so"
    else
        echo "  ! Missing: $SO (skipping ABI $ABI)"
    fi
done

# Copy assets (hooks.dex was already generated to module/assets/)
mkdir -p "$MODULE_STAGING/assets"
cp "$SCRIPT_DIR/module/assets/hooks.dex" "$MODULE_STAGING/assets/hooks.dex"

# ── Pack the ZIP ──────────────────────────────────────────────────────────────
ZIP_OUT="$SCRIPT_DIR/lineagehide.zip"
rm -f "$ZIP_OUT"
(cd "$MODULE_STAGING" && zip -r "$ZIP_OUT" . -x "*.DS_Store" -x "__MACOSX/*")
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Build complete: $ZIP_OUT"
echo " $(du -h "$ZIP_OUT" | cut -f1)  $(ls "$MODULE_STAGING/zygisk/" | tr '\n' ' ')"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
