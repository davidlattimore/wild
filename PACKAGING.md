# Recommendations for Packaging Wild linker

## Binaries

This repository consists of Wild linker and linker-diff binaries. We recommend providing `wild`
binary and symlink `ld.wild` pointing to it. This enables `-fuse-ld=wild` usage with Clang.
Linker-diff is mainly a tool to aid Wild development, so you most likely don't want to package it.

## Building

This project uses Cargo as its build system. Wild's official artifacts are built using with
`--profile dist` that enables compiler's internal ThinLTO and strips the binaries. The benefit
from ThinLTO is very mild in Wild's case, so it's up to you whether to use it. Musl artifacts
also use `--feature mimalloc`, see below for the explanation.

### Optional features

Wild has two optional features:

- `fork` (enabled by default) – an optimisation of cleanup phase using `fork()`. Can be disabled in
  the runtime via `--no-fork` flag.
- `mimalloc` (disabled by default) – build and use Mimalloc as the allocator instead of the system
  one. It performs marginally worse than Glibc in Wild's case, but much better than Musl.

## Testing

To test built binary, you can use `cargo test`, preferably with the same configuration as the build
to avoid rebuilding. The testsuite is configured with `test-config.toml` file (default values are
used if absent). To tweak the configuration, you can copy `test-config.toml.example` to
`test-config.toml` and edit it to your liking. Just be careful with `run_all_diffs` option, it's
meant mostly for Wild development and may cause false positives.