#!/usr/bin/env bash
# Materialise the `wasm-tokei` benchmark save-dir.
#
# Builds tokei (XAMPPRocky/tokei, a pure-rust LOC counter) for
# `wasm32-wasip2`, captures the rustc→linker invocation via
# capture-link.sh, and lays the result down as a save-dir the
# bench-runner can replay.
#
# Usage:
#   ./build-wasm-tokei.sh <out-dir> [tokei-revision]
#
# Example:
#   ./benchmarks/wasm-savedirs/build-wasm-tokei.sh \
#       /tmp/wild-saves-wasm/wasm-tokei
#
# The save-dir produced contains:
#   inputs/                — every .o / .rlib rustc passed to wasm-ld
#   run-with               — replays the link, branches between wild
#                            (`--target wasm32`) and wasm-ld
#   argv.txt               — original linker argv for forensics
#   build/                 — the cargo build dir (kept so subsequent
#                            re-runs are incremental).
set -euo pipefail

OUT_DIR="${1:?usage: $0 <out-dir> [tokei-revision]}"
REV="${2:-master}"

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
CAPTURE="$SCRIPT_DIR/capture-link.sh"

# Locate a wasm-ld (rust-lld's wasm front-end). Prefer an
# explicit env override; otherwise pick the first one we find in
# any installed rustup toolchain.
WASM_LD="${WASM_LD:-}"
if [ -z "$WASM_LD" ]; then
    WASM_LD=$(find "$HOME/.rustup/toolchains" -name wasm-ld 2>/dev/null | head -n1 || true)
fi
if [ -z "$WASM_LD" ] || [ ! -x "$WASM_LD" ]; then
    echo "ERROR: no wasm-ld found. Set WASM_LD=/path/to/wasm-ld or add a rustup toolchain that ships rust-lld." >&2
    exit 2
fi

mkdir -p "$OUT_DIR"
BUILD_DIR="$OUT_DIR/build"
mkdir -p "$BUILD_DIR"

# Clone tokei into the build dir if not already present. Use a
# shallow clone — we don't need the history.
if [ ! -d "$BUILD_DIR/tokei/.git" ]; then
    echo "Cloning tokei..."
    git clone --depth 1 --branch "$REV" \
        https://github.com/XAMPPRocky/tokei.git "$BUILD_DIR/tokei"
fi

# Make sure the toolchain has the wasm32-wasip2 target.
rustup target add wasm32-wasip2 2>/dev/null || true

# Drive the build through capture-link.sh.
echo "Building tokei → wasm32-wasip2 (capturing link)..."
(
    cd "$BUILD_DIR/tokei"
    # Force a re-link by removing tokei's prior wasm artefact —
    # cargo otherwise short-circuits and never invokes the linker.
    rm -f target/wasm32-wasip2/release/tokei.wasm
    CARGO_TARGET_WASM32_WASIP2_LINKER="$CAPTURE" \
    WASM_LINK_REAL="$WASM_LD" \
    WASM_LINK_SAVE_DIR="$OUT_DIR" \
    WASM_LINK_SAVE_FILTER="tokei.wasm" \
        cargo build --release --target wasm32-wasip2 --bin tokei
)

# Sanity check: the save-dir should now contain a run-with + inputs.
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
echo "  OUT=/tmp/tokei.wasm $OUT_DIR/run-with $WASM_LD"
echo "  OUT=/tmp/tokei.wasm $OUT_DIR/run-with /path/to/wild"
