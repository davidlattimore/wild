# Recommendations for Packaging Wild linker

## Binaries

This repository consists of Wild linker and linker-diff binaries. We recommend providing the `wild`
binary and symlink `ld.wild` pointing to it, as this enables `-fuse-ld=wild` usage with Clang.
Linker-diff is mainly a tool to aid Wild development, so you most likely don't want to package it.

## Building

This project uses Cargo as its build system. The official releases are built with `--profile dist`
that enables stripping of the binaries. Musl releases also enable `--feature mimalloc`, see below
for the explanation.

### Optional features

Wild has two optional build-time features:

- `fork` (enabled by default) – an optimisation of process clean-up phase using `fork()`. Can be
  disabled in the runtime via `--no-fork` flag.
- `mimalloc` (disabled by default) – build and use Mimalloc as the allocator instead of the system
  one. It performs marginally worse than Glibc in Wild's case, but much better than Musl.

## Testing

To test built binary, you can use `cargo test`, preferably with the same configuration as the build
to avoid rebuilding. The testsuite is configured with `test-config.toml` file (default values are
used if absent) and `WILD_TEST_IGNORE_FORMAT`.

To tweak the configuration, you can copy `test-config.toml.example` to `test-config.toml` and edit
it to your liking. You can learn more about the options
at [Configuration file for tests](./CONTRIBUTING.md#configuration-file-for-tests). Just be careful
with `run_all_diffs` option, it's meant mostly for Wild development and may cause false positives.

Setting `WILD_TEST_IGNORE_FORMAT` disables format checks of C/C++ source files in tests which you
might prefer because your `clang-format` may give different results.

## Issues

If you, or the users of your package, encounter any issues or pain points with Wild, don't hesitate
to report them to us or reach out for help.
