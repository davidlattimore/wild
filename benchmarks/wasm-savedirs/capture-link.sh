#!/usr/bin/env bash
# shellcheck disable=SC2016
# (Several `printf` blocks below emit literal `$OUT`/`$D` placeholders
# into the generated `run-with` script — bash in the bench harness
# expands them later, not here. SC2016 noise is suppressed file-wide.)
#
# Generic Cargo `target.<wasm-triple>.linker` shim that captures a
# rustc-driven wasm link into a benchmark save-dir.
#
# Set as Cargo's wasm linker:
#
#   CARGO_TARGET_WASM32_WASIP2_LINKER=$PWD/capture-link.sh \
#   WASM_LINK_REAL=/path/to/real/wasm-ld          \
#   WASM_LINK_SAVE_DIR=$PWD/saves/wasm-tokei      \
#       cargo build --release --target wasm32-wasip2
#
# Per invocation:
#   1. Records argv to <save-dir>/argv.txt.
#   2. Copies any positional path arg ending in .o/.rlib/.a into
#      <save-dir>/inputs/ and rewrites the args to point at the
#      copies (keeps relative ordering, so `--whole-archive ... -lfoo
#      libbar.rlib` shapes round-trip).
#   3. Writes <save-dir>/run-with: invokes the supplied linker
#      ($1) on the captured args, with `--target wasm32` injected
#      iff $1's basename matches `wild`. The bench-runner uses
#      this convention so wasm-ld doesn't choke on a wild-only flag.
#   4. Forwards the whole call to $WASM_LINK_REAL so cargo's build
#      finishes successfully (we want the workload to actually link
#      so subsequent `cargo build` invocations don't re-run rustc).
#
# Multi-link safety: cargo can invoke the linker many times during
# one build (per-crate codegen, build scripts, etc.). We only keep
# the LAST one — later invocations overwrite earlier saves. Filter
# via WASM_LINK_SAVE_FILTER (a substring; only invocations whose
# argv contains it are saved). Default: "" (save every invocation,
# keep the last).
set -euo pipefail

: "${WASM_LINK_REAL:?WASM_LINK_REAL must point at the underlying wasm linker (e.g. wasm-ld)}"
: "${WASM_LINK_SAVE_DIR:?WASM_LINK_SAVE_DIR must point at where the save-dir should be materialised}"

SAVE_DIR="$WASM_LINK_SAVE_DIR"
FILTER="${WASM_LINK_SAVE_FILTER:-}"

ARGS=("$@")

# rustc invokes the wasm linker as `rust-lld -flavor wasm ARGS`, but
# the standalone `wasm-ld` symlink (and wild) reject `-flavor` —
# wasm-ld is already fixed at the wasm flavour by its filename, and
# wild uses `--target wasm32`. Strip the `-flavor <value>` pair
# (rustc emits both `-flavor wasm` and `-flavor=wasm` shapes) before
# either saving or forwarding so the run-with replays cleanly under
# both linker kinds.
FILTERED=()
skip_next=0
for arg in "${ARGS[@]}"; do
    if [ "$skip_next" -eq 1 ]; then
        skip_next=0
        continue
    fi
    case "$arg" in
        -flavor) skip_next=1 ;;
        -flavor=*) ;;
        *) FILTERED+=("$arg") ;;
    esac
done
ARGS=("${FILTERED[@]}")

ALL_ARGS_STR=" ${ARGS[*]} "
SHOULD_SAVE=1
if [ -n "$FILTER" ] && ! [[ "$ALL_ARGS_STR" == *"$FILTER"* ]]; then
    SHOULD_SAVE=0
fi

if [ "$SHOULD_SAVE" -eq 1 ]; then
    mkdir -p "$SAVE_DIR/inputs"
    # Wipe stale inputs so a multi-cargo-link run captures only the
    # current invocation's set, not an accumulating union.
    rm -f "$SAVE_DIR/inputs"/*

    # Rewrite positional path args (.o/.rlib/.a) to copies under
    # inputs/. Non-path args pass through unchanged. Output flags
    # (`-o <path>`) get rewritten to `-o $OUT` in the run-with.
    REWRITTEN=()
    OUTPUT_PATH=""
    skip_next=0
    for i in "${!ARGS[@]}"; do
        arg="${ARGS[$i]}"
        if [ "$skip_next" -eq 1 ]; then
            skip_next=0
            continue
        fi
        case "$arg" in
            -o)
                OUTPUT_PATH="${ARGS[$((i+1))]}"
                REWRITTEN+=(-o '$OUT')
                skip_next=1
                ;;
            *.o|*.rlib|*.a)
                if [ -f "$arg" ]; then
                    base=$(basename "$arg")
                    cp "$arg" "$SAVE_DIR/inputs/$base"
                    REWRITTEN+=("\$D/inputs/$base")
                else
                    REWRITTEN+=("$arg")
                fi
                ;;
            *)
                REWRITTEN+=("$arg")
                ;;
        esac
    done

    # Save the original argv for forensics.
    {
        printf '%s\n' "${ARGS[@]}"
    } > "$SAVE_DIR/argv.txt"

    # Emit the run-with. The `case` injects `--target wasm32` when
    # invoked with wild (basename match — wild needs the flag, wasm-ld
    # rejects it). The bench-runner appends extra flags via "$@" after
    # the linker, before our captured args.
    {
        printf '#!/usr/bin/env bash\n'
        printf 'set -euo pipefail\n'
        printf 'D=$(cd "$(dirname "$0")" && pwd)\n'
        printf 'LINKER="$1"; shift\n'
        printf ': "${OUT:?OUT env var must be set by the bench harness}"\n'
        printf 'EXTRA_TARGET=()\n'
        printf 'case "$(basename "$LINKER")" in\n'
        printf '    wild|wild-*) EXTRA_TARGET=(--target wasm32) ;;\n'
        printf 'esac\n'
        printf 'exec "$LINKER" "${EXTRA_TARGET[@]}" "$@"'
        for arg in "${REWRITTEN[@]}"; do
            # Quote-escape: single-quote anything that isn't the $D /
            # $OUT placeholder. Splice the placeholder bare so bash
            # expands it.
            case "$arg" in
                '$OUT'|\$D/*) printf ' %s' "$arg" ;;
                *) printf ' %q' "$arg" ;;
            esac
        done
        printf '\n# Original output: %s\n' "$OUTPUT_PATH"
    } > "$SAVE_DIR/run-with"
    chmod +x "$SAVE_DIR/run-with"
fi

# Forward to the real linker so cargo's build succeeds.
exec "$WASM_LINK_REAL" "${ARGS[@]}"
