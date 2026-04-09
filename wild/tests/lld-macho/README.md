# lld MachO Test Suite

These tests are adapted from LLVM lld's MachO linker test suite.

## Source

<https://github.com/llvm/llvm-project/tree/main/lld/test/MachO>

## License

Apache License v2.0 with LLVM Exceptions — see [LICENSE.TXT](LICENSE.TXT).

## Format

Tests use LLVM's LIT format:

- `# RUN:` directives show how to assemble and link
- `# CHECK:` directives show expected output
- `# REQUIRES: aarch64` means the test needs ARM64 support
- `split-file %s %t` splits the file at `#---` markers

## Usage with Wild

To run a test manually:

```sh
# Assemble (strip RUN/CHECK comments first)
grep -v '^#' test.s > clean.s
clang -c -target arm64-apple-macos clean.s -o test.o

# Link with Wild
wild test.o -dylib -arch arm64 -lSystem -o test.dylib

# Verify with objdump
objdump --macho -d test.dylib
```

## Cherry-picking new tests

To add tests from upstream lld:

```sh
# Sparse checkout the lld tests
git clone --depth 1 --filter=blob:none --sparse \
  https://github.com/llvm/llvm-project.git /tmp/llvm
cd /tmp/llvm && git sparse-checkout set lld/test/MachO

# Copy desired tests
cp /tmp/llvm/lld/test/MachO/new-test.s wild/tests/lld-macho/
```
