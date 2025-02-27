# Wild linker

Wild is a linker with the goal of being very fast for iterative development.

The plan is to eventually make it incremental, however that isn't yet implemented. It is however
already pretty fast even without incremental linking.

For production builds, its recommended to use a more mature linker like GNU ld or LLD.

During development, if you'd like faster warm build times, then you could give Wild a try. It's at
the point now where it should be usable for development purposes provided you're developing on
x86-64 Linux. If you hit any issues, please file a bug report.

## Installation

To install a pre-built binary, you can copy and paste the command from the [releases
page](https://github.com/davidlattimore/wild/releases). Alternatively, you can download the tarball
and manually copy the `wild` binary somewhere on your path.

To build and install, you can run:

```sh
cargo install --locked --bin wild --git https://github.com/davidlattimore/wild.git wild
```

## Using as your default linker

If you'd like to use Wild as your default linker for building Rust code, you can put the following
in `~/.cargo/config.toml`.

```toml
[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-C", "link-arg=--ld-path=wild"]
```

## Q&A

### Why another linker?

Mold is already very fast, however it doesn't do incremental linking and the author has stated that
they don't intend to. Wild doesn't do incremental linking yet, but that is the end-goal. By writing
Wild in Rust, it's hoped that the complexity of incremental linking will be achievable.

### What's working?

The following platforms / architectures are currently supported:

* x86-64 on Linux
* ARM64 on Linux

The following is working with the caveat that there may be bugs:

* Output to statically linked, non-relocatable binaries
* Output to statically linked, position-independent binaries (static-PIE)
* Output to dynamically linked binaries
* Output to shared objects (.so files)
* Rust proc-macros, when linked with Wild work
* Most of the top downloaded crates on crates.io have been tested with Wild and pass their tests
* Debug info

### What isn't yet supported?

Lots of stuff. Here are some of the larger things that aren't yet done, roughly sorted by current
priority:

* Incremental linking
* Support for more architectures
* Support for a wider range of linker flags
* Linker scripts
* Mac support
* Windows support
* LTO

### How can I verify that Wild was used to link a binary?

Install `readelf`, then run:

```sh
readelf  -p .comment my-executable
```

Look for a line like:

```
Linker: Wild version 0.1.0
```

Or if you don't want to install readelf, you can probably get away with:

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

These benchmark were run on David Lattimore's laptop (2020 model System76 Lemur pro), which has 4
cores (8 threads) and 42 GB of RAM.

The following times are for linking rustc-driver, which is a shared object that contains most of the
code of the Rust compiler. Linking was done with with `--strip-debug` and `--build-id=none`.

| Linker            | Time (ms) | ± Standard deviation (ms) |
|-------------------|-----------|---------------------------|
| GNU ld (2.38)     | 20774     | 855                       |
| gold (2.38)       | 6796      | 58                        |
| lld (18.1.8)      | 1601      | 24                        |
| mold (2.34.1)     | 946       | 17                        |
| wild (2024-11-30) | 486       | 19                        |

The following times are for linking the C compiler, clang without debug info.

| Linker            | Time (ms) | ± Standard deviation (ms) |
|-------------------|-----------|---------------------------|
| GNU ld (2.38)     | 8784      | 42                        |
| gold (2.38)       | 2528      | 37                        |
| lld (18.1.8)      | 1679      | 23                        |
| mold (2.34.1)     | 429       | 2                         |
| wild (2024-11-30) | 244       | 6                         |

Next, let's add debug info (remove `--strip-debug`). First rustc-driver:

| Linker            | Time (ms) | ± Standard deviation (ms) |
|-------------------|-----------|---------------------------|
| GNU ld (2.38)     | 23224     | 1030                      |
| gold (2.38)       | 8840      | 879                       |
| lld (18.1.8)      | 2741      | 1403                      |
| mold (2.34.1)     | 3514      | 2102                      |
| wild (2024-11-30) | 3158      | 1616                      |

Now clang with debug info:

| Linker            | Time (ms) | ± Standard deviation (ms) |
|-------------------|-----------|---------------------------|
| GNU ld (2.38)     | 139985    | 9871                      |
| gold (2.38)       | 92147     | 7287                      |
| lld (18.1.8)      | 30549     | 9819                      |
| mold (2.34.1)     | 16933     | 5359                      |
| wild (2024-11-30) | 31540     | 7133                      |

So Wild performs pretty well without debug info, but with debug info, it's performing less well at
the moment.

See [BENCHMARKING.md](BENCHMARKING.md) for more details on benchmarking.

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
