# Wild linker

Wild is a linker with the goal of being very fast for iterative development.

The plan is to eventually make it incremental, however that isn't yet implemented. It is however
already pretty fast even without incremental linking.

## Installation

### From GitHub releases

Download a tarball from the [releases page](https://github.com/davidlattimore/wild/releases). Unpack
it and copy the `wild` binary somewhere on your path.

### Cargo binstall

If you have [cargo-binstall](https://github.com/cargo-bins/cargo-binstall), you can install wild as
follows:

```sh
cargo binstall wild-linker
```

### Build latest release from crates.io

```sh
cargo install --locked wild-linker
```

### Build from git head

To build and install the latest, unreleased code:

```sh
cargo install --locked --bin wild --git https://github.com/davidlattimore/wild.git wild-linker
```

### Nix

To use a stable Wild from Nixpkgs:

```nix
let
 wildStdenv = pkgs.useWildLinker pkgs.stdenv;
in
pkgs.callPackage ./package { stdenv = wildStdenv; }  
```

to use the latest unstable git revision of wild, see [the nix documentation](./nix/nix.md)

## Using as your default linker

If you'd like to use Wild as your default linker for building Rust code, you can put the following
in `~/.cargo/config.toml`.

On Linux:
```toml
[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-Clink-arg=--ld-path=wild"]
```

On Illumos:
```
[target.x86_64-unknown-illumos]
# Absolute path to clang - on OmniOS this is likely something like /opt/ooce/bin/clang.
linker = "/usr/bin/clang"

rustflags = [
    # Will silently delegate to GNU ld or Sun ld unless the absolute path to Wild is provided.
    "-Clink-arg=-fuse-ld=/absolute/path/to/wild"
]
```

## Using wild in CI

If you'd like to use Wild as your linker for Rust code in CI, see
[wild-action](https://github.com/davidlattimore/wild-action).

## Q&A

### Why another linker?

Mold is already very fast, however it doesn't do incremental linking and the author has stated that
they don't intend to. Wild doesn't do incremental linking yet, but that is the end-goal. By writing
Wild in Rust, it's hoped that the complexity of incremental linking will be achievable.

### What's working?

The following platforms / architectures are currently supported:

* x86-64 on Linux
* ARM64 on Linux
* RISC-V (riscv64gc) on Linux (initial support: [#678](https://github.com/davidlattimore/wild/issues/678))

The following is working with the caveat that there may be bugs:

* Output to statically linked, non-relocatable binaries
* Output to statically linked, position-independent binaries (static-PIE)
* Output to dynamically linked binaries
* Output to shared objects (.so files)
* Rust proc-macros, when linked with Wild work
* Most of the top downloaded crates on crates.io have been tested with Wild and pass their tests
* Debug info
* GNU jobserver support
* Very basic linker script support (section mapping, keeping sections, alignment, defining start /
  stop symbols).

### What isn't yet supported?

Lots of stuff. Here are some of the larger things that aren't yet done, roughly sorted by current
priority:

* Incremental linking
* Support for more architectures
* Support for a wider range of linker flags
* More complex linker scripts
* Mac support
* Windows support
* LTO

### How can I verify that Wild was used to link a binary?

Install `readelf` (available from binutils package), then run:

```sh
readelf --string-dump .comment my-executable
```

Look for a line like:

```
Linker: Wild version 0.1.0
```

You can probably also get away with `strings` (also available from binutils package):

```sh
strings my-executable | grep 'Linker:'
```

### Where did the name come from?

It's somewhat of a tradition for linkers to end with the letters "ld". e.g. "GNU ld, "gold", "lld",
"mold". Since the end-goal is for the linker to be incremental, an "I" is added. Let's say the "W"
stands for "Wild", since recursive acronyms are popular in open-source projects.

## Benchmarks

The goal of Wild is to eventually be very fast via incremental linking. However, we also want to be
as fast as we can be for non-incremental linking and for the initial link when incremental linking
is enabled.

See [BENCHMARKING.md](BENCHMARKING.md) for more details on running benchmarks.

All benchmarks are run with output to a tmpfs.

Wild currently doesn't perform great beyond 8 threads. This is something we've been investigating
and hope to improve soon.

### X86_64

X86_64 benchmarks were run on David Lattimore's laptop (2020 model System76 Lemur pro), which has 4 cores
(8 threads) and 42 GB of RAM.

Binaries used are official release builds from each project.

First a benchmark is linking a smallish binary, the wild linker itself.

![Benchmark of lld, mold and wild linking wild](images/benchmarks/wild.svg)

Next, we link librustc-driver, which is a shared object and is where most of the code in the rust
compiler ends up.

![Benchmark of lld, mold and wild linking librustc-driver](images/benchmarks/librustc-driver.svg)

Finally, for an especially large binary, we link the chromium web browser with debug info.

![Benchmark of lld, mold and wild linking chromium](images/benchmarks/chromium.svg)

### Aarch64

Aarch64 benchmarks were run on RaspberryPi5 with 8 GiB of RAM. Binaries used are official release
binaries from each project.

![Benchmark of lld, mold and wild linking wild without debug info on a RaspberryPi5](images/benchmarks/rpi-wild-no-debug.svg)

![Benchmark of lld, mold and wild linking wild with debug info on a RaspberryPi5](images/benchmarks/rpi-wild-debug.svg)


### RISC-V 64

RISC-V benchmarks were run on a VisionFive2 with 8 GiB of RAM running Ubuntu 24.04.

Neither wild nor lld have official release binaries for RISC-V. For wild, the binary was just a
locally built release binary. For lld, the version that comes with Ubuntu was used. Mold does have
an official release binary for RISC-V, so that was used.

![Benchmark of lld, mold and wild linking wild with debug info on a VF2](images/benchmarks/risc-v-64-wild-debug.svg)

![Benchmark of lld, mold and wild linking wild with --strip-debug info on a VF2](images/benchmarks/risc-v-64-wild-non-debug.svg)

## Linking Rust code

The following is a `cargo test` command-line that can be used to build and test a crate using Wild.
This has been run successfully on a few popular crates (e.g. ripgrep, serde, tokio, rand, bitflags).
It assumes that the "wild" binary is on your path. It also depends on the Clang compiler being
installed, since GCC doesn't allow using an arbitrary linker.

```sh
RUSTFLAGS="-Clinker=clang -Clink-args=--ld-path=wild" cargo test
```

## Contributing

For more information on contributing to `wild` see [CONTRIBUTING.md](CONTRIBUTING.md).

For a high-level overview of Wild's design, see [DESIGN.md](DESIGN.md).

## Chat server

We have a Zulip server for Wild-related chat. You can join
[here](https://wild.zulipchat.com/join/bbopdeg6howwjpaiyowngyde/).

## Further reading

Many of the posts on [David's blog](https://davidlattimore.github.io/) are about various aspects of
the Wild linker.

## Sponsorship

If you'd like to [sponsor this work](https://github.com/sponsors/davidlattimore), that would be very
much appreciated. The more sponsorship I get the longer I can continue to work on this project full
time.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
Wild by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
