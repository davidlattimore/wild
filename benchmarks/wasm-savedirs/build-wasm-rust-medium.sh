#!/usr/bin/env bash
# Materialise the `wasm-rust-medium` benchmark save-dir.
#
# Builds the small custom Rust workload in
# `benchmarks/wasm-savedirs/wasm-rust-medium/` for `wasm32-wasip2`,
# captures the rustc → linker invocation via capture-link.sh, and
# lays the result down as a save-dir the bench-runner can replay.
#
# Usage:
#   ./build-wasm-rust-medium.sh <out-dir>
#
# Example:
#   ./benchmarks/wasm-savedirs/build-wasm-rust-medium.sh \
#       /tmp/wild-saves-wasm/wasm-rust-medium
set -euo pipefail

OUT_DIR="${1:?usage: $0 <out-dir>}"

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
CAPTURE="$SCRIPT_DIR/capture-link.sh"
SOURCE_DIR="$SCRIPT_DIR/wasm-rust-medium"

# Locate a wasm-ld (rust-lld's wasm front-end). Prefer an explicit
# env override; otherwise pick the first one we find in any
# installed rustup toolchain. The capture script forwards every
# call to this so cargo's link step actually finishes.
WASM_LD="${WASM_LD:-}"
if [ -z "$WASM_LD" ]; then
    WASM_LD=$(find "$HOME/.rustup/toolchains" -name wasm-ld 2>/dev/null | head -n1 || true)
fi
if [ -z "$WASM_LD" ] || [ ! -x "$WASM_LD" ]; then
    echo "ERROR: no wasm-ld found. Set WASM_LD=/path/to/wasm-ld or add a rustup toolchain that ships rust-lld." >&2
    exit 2
fi

mkdir -p "$OUT_DIR"

# Make sure the toolchain has the wasm32-wasip2 target.
rustup target add wasm32-wasip2 2>/dev/null || true

# Drive the build through capture-link.sh. We use a separate
# CARGO_TARGET_DIR per save-dir so re-running for one bench
# doesn't churn another bench's incremental state.
echo "Building wasm-rust-medium → wasm32-wasip2 (capturing link)..."
TARGET_DIR="$OUT_DIR/target"
(
    cd "$SOURCE_DIR"
    rm -f "$TARGET_DIR/wasm32-wasip2/release/wasm-rust-medium.wasm"
    CARGO_TARGET_DIR="$TARGET_DIR" \
    CARGO_TARGET_WASM32_WASIP2_LINKER="$CAPTURE" \
    WASM_LINK_REAL="$WASM_LD" \
    WASM_LINK_SAVE_DIR="$OUT_DIR" \
    WASM_LINK_SAVE_FILTER="wasm-rust-medium" \
        cargo build --release --target wasm32-wasip2
)

if [ ! -x "$OUT_DIR/run-with" ]; then
    echo "ERROR: capture didn't produce $OUT_DIR/run-with — was the linker invoked?" >&2
    echo "Dump of save-dir:" >&2
    ls -la "$OUT_DIR" >&2
    exit 3
fi

INPUT_BYTES=$(du -sk "$OUT_DIR/inputs" | awk '{print $1}')
N_INPUTS=$(find "$OUT_DIR/inputs" -type f | wc -l | tr -d ' ')
echo
echo "Save-dir ready: $OUT_DIR"
echo "  inputs: $N_INPUTS files, ${INPUT_BYTES} KiB total"
echo
echo "Smoke-test:"
echo "  OUT=/tmp/medium.wasm $OUT_DIR/run-with $WASM_LD"
echo "  OUT=/tmp/medium.wasm $OUT_DIR/run-with /path/to/wild"
