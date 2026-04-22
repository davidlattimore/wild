#!/usr/bin/env bash
# wild wasm LTO bench harness (P7).
#
# Builds the partner-chains-demo-runtime under several linker +
# optimisation configurations and records final wasm sizes + link
# wall-clock time. Results go to stdout in tab-separated form so
# they can be pasted into wasm-lto.md.
#
# Prerequisites:
#   - $WILD = path to the wild binary (symlinked as wasm-ld)
#   - $PC   = path to the partner-chains checkout
#   - $RUST_LLD = path to rust-lld for the baseline
#   - llc on $PATH (for LTO paths that shell out)
#
# Usage:
#   WILD=/tmp/wild-wasm-shim/wasm-ld \
#   PC=~/git/midnightntwrk/partner-chains \
#   RUST_LLD=$(find ~/.rustup/toolchains/1.94.0-aarch64-apple-darwin -name rust-lld | head -1) \
#   bash benches/wasm-lto-bench.sh

set -euo pipefail

# Bail with a clear message if the build or the post-build size
# probe fails, so a hanging linker doesn't get masked by a
# downstream `tee` returning 0. Also cap each cargo invocation at
# 5 minutes — any single config taking longer is a hang to debug,
# not a measurement.
fail() { echo "BENCH FAIL: $*" >&2; exit 2; }
PER_CONFIG_TIMEOUT=${PER_CONFIG_TIMEOUT:-300}

: "${WILD:?must be set (path to wild as wasm-ld)}"
: "${PC:?must be set (path to partner-chains checkout)}"
: "${RUST_LLD:?must be set (path to rust-lld)}"

RUNTIME_PKG="partner-chains-demo-runtime"
# Cargo normalises dashes to underscores for the emitted wasm file.
RUNTIME_STEM="partner_chains_demo_runtime"
ARTEFACT_DIR="$PC/target/release/wbuild/$RUNTIME_PKG"
WASM="$ARTEFACT_DIR/target/wasm32v1-none/release/$RUNTIME_STEM.wasm"
COMPACT="$ARTEFACT_DIR/$RUNTIME_STEM.compact.wasm"
COMPRESSED="$ARTEFACT_DIR/$RUNTIME_STEM.compact.compressed.wasm"

bench_one() {
    local label="$1" linker="$2" extra_rustflags="$3"

    # Force re-link: nuke the cached wasm + touch build.rs so
    # substrate-wasm-builder re-invokes the inner cargo. We don't
    # wipe target dirs entirely — that would measure the host-side
    # build, which isn't what we care about here.
    rm -f "$WASM" "$COMPACT" "$COMPRESSED"
    touch "$PC/demo/runtime/build.rs"

    local start
    start=$(date +%s)
    # shellcheck disable=SC2086
    ( cd "$PC" && \
      CARGO_TARGET_WASM32V1_NONE_LINKER="$linker" \
      WASM_BUILD_RUSTFLAGS="$extra_rustflags" \
      timeout "$PER_CONFIG_TIMEOUT" cargo build -p "$RUNTIME_PKG" --release \
          >/tmp/wasm-lto-bench.last.log 2>&1 ) \
      || fail "[$label] cargo build exited non-zero (or timed out at ${PER_CONFIG_TIMEOUT}s); see /tmp/wasm-lto-bench.last.log"
    local elapsed=$(( $(date +%s) - start ))

    [ -f "$WASM" ] || fail "[$label] $WASM was not produced; see /tmp/wasm-lto-bench.last.log"
    local raw_size compact_size compressed_size
    raw_size=$(stat -f%z "$WASM" 2>/dev/null || stat -c%s "$WASM")
    compact_size=$(stat -f%z "$COMPACT" 2>/dev/null || stat -c%s "$COMPACT" 2>/dev/null || echo -)
    compressed_size=$(stat -f%z "$COMPRESSED" 2>/dev/null || stat -c%s "$COMPRESSED" 2>/dev/null || echo -)

    printf "%-32s\t%4ds\t%10d\t%10s\t%10s\n" \
        "$label" "$elapsed" "$raw_size" "$compact_size" "$compressed_size"
}

printf "%-32s\t%5s\t%10s\t%10s\t%10s\n" \
    "config" "wall" "raw.wasm" "compact" "compressed"

# (a) rust-lld baseline
bench_one "rust-lld baseline"        "$RUST_LLD"  ""

# (b) wild -O0 (no wilt optimiser)
bench_one "wild -O0 (raw)"           "$WILD"       "-C link-arg=-O0"

# (c) wild -O1 (wilt basic)
bench_one "wild -O1 (wilt)"          "$WILD"       "-C link-arg=-O1"

# (d) wild -O3 (wilt + strip-debug, rustc default)
bench_one "wild -O3 (wilt + strip)"  "$WILD"       ""
