#!/usr/bin/env bash
# Updates the vendored LLD ELF tests from a local llvm-project checkout.
#
# Usage:
#   external_test_suites/lld/update-lld-tests.sh <path-to-llvm-project>
#
# Example:
#   external_test_suites/lld/update-lld-tests.sh ~/Desktop/Deepak/llvm-project

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <path-to-llvm-project>" >&2
    exit 1
fi

LLVM_PROJECT="$1"
SRC="$LLVM_PROJECT/lld/test/ELF"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="$SCRIPT_DIR/test/ELF"

if [[ ! -d "$SRC" ]]; then
    echo "error: $SRC does not exist. Is '$LLVM_PROJECT' a valid llvm-project checkout?" >&2
    exit 1
fi

mkdir -p "$DEST"

# Mirror the upstream test directory, removing anything locally that no
# longer exists upstream, so stale/removed tests don't linger.
rsync -a --delete "$SRC/" "$DEST/"

echo "Vendored LLD ELF tests from $SRC to $DEST"
echo "Review the diff and update lld_skip_tests.toml as needed."
