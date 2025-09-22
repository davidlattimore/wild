# Wild linker

Wild is a linker with the goal of being very fast for iterative development.

The plan is to eventually make it incremental, however that isn't yet implemented. It is however
already pretty fast even without incremental linking.

For production builds, it's recommended to use a more mature linker like GNU ld or LLD.

During development, if you'd like faster warm build times, then you could give Wild a try. It's at
the point now where it should be usable for development purposes provided you're developing on
x86-64 Linux. If you hit any issues, please file a bug report.

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

Wild include a flake, a derivation for building Wild, and a stdenv adapter
in-tree. If the overlay is applied these are provided for you. Just add it to
your flake inputs. A devShell example is also shown with the flake.

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nix/nixos-unstable";
    wild = {
      url = "github:davidlattimore/wild";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      wild,
    }:
    let
      pkgs = import nixpkgs {
        system = "x86_64-linux";
        overlays = [
          (import wild)
        ];
      };

      wildStdenv = pkgs.useWildLinker pkgs.stdenv;
    in
    {
      packages.x86_64-linux.default = pkgs.callPackage ./package.nix { stdenv = wildStdenv; };

      devShell.x86_64-linux.default = pkgs.mkShell.override { stdenv = wildStdenv; } {
        inputsFrom = [ self.packages.x86_64-linux.default ];
        packages = [
          pkgs.rust-analyzer
        ];
      };
    };
}
```
Without flakes (npins shown):

1. `$ npins add github davidlattimore wild -b main`

```nix
let
  sources = import ./npins;
  pkgs = import sources.nixpkgs {
    overlays = [
      (import sources.wild)
    ];
  };
  wildStdenv = pkgs.useWildLinker pkgs.stdenv;
in
{
  package = pkgs.callPackage ./package.nix { stdenv = wildStdenv; };
}
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
* RISC-V (riscv64gc) on Linux (initial support: [#678](https://github.com/davidlattimore/wild/issues/678))

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

See [BENCHMARKING.md](BENCHMARKING.md) for more details on running benchmarks.

All benchmarks are run with output to a tmpfs.

### Linking clang on x86-64

This benchmark was run on David Lattimore's laptop (2020 model System76 Lemur pro), which has 4
cores (8 threads) and 42 GB of RAM.

First, without debug info:

```
❯ OUT=/home/david/ttt throttle-count hyperfine --warmup 1 -N -n lld-18 './run-with ld.lld --strip-debug' -n mold-2.36-no-fork './run-with mold --no-fork --strip-debug' -n wild-0.4.0-no-fork './run-with wild --no-fork --strip-debug' -n mold-2.36 './run-with mold --strip-debug' -n wild-0.4.0 './run-with wild --strip-debug'
temp: +40.0°C
Benchmark 1: lld-18
  Time (mean ± σ):     514.1 ms ±   5.1 ms    [User: 1000.1 ms, System: 451.9 ms]
  Range (min … max):   507.1 ms … 523.4 ms    10 runs
 
Benchmark 2: mold-2.36-no-fork
  Time (mean ± σ):     388.5 ms ±   5.3 ms    [User: 1986.9 ms, System: 436.2 ms]
  Range (min … max):   379.0 ms … 396.8 ms    10 runs
 
Benchmark 3: wild-0.4.0-no-fork
  Time (mean ± σ):     244.4 ms ±   3.2 ms    [User: 1087.5 ms, System: 313.0 ms]
  Range (min … max):   240.3 ms … 251.7 ms    12 runs
 
Benchmark 4: mold-2.36
  Time (mean ± σ):     365.7 ms ±   8.5 ms    [User: 9.4 ms, System: 3.1 ms]
  Range (min … max):   358.1 ms … 384.9 ms    10 runs
 
Benchmark 5: wild-0.4.0
  Time (mean ± σ):     220.5 ms ±   3.4 ms    [User: 2.6 ms, System: 2.0 ms]
  Range (min … max):   214.1 ms … 226.1 ms    13 runs
 
Summary
  'wild-0.4.0' ran
    1.11 ± 0.02 times faster than 'wild-0.4.0-no-fork'
    1.66 ± 0.05 times faster than 'mold-2.36'
    1.76 ± 0.04 times faster than 'mold-2.36-no-fork'
    2.33 ± 0.04 times faster than 'lld-18'
Throttle pkg: 0 core: 0 ms: 0 temp: +59.0°C
```

Note, the user and system CPU times for mold and wild when run with default flags are meaningless,
since these linkers fork by default and hyperfine doesn't see the CPU usage of the forked
subprocess. For accurate CPU usage, see the no-fork variants. For later benchmarks, we always
include `--no-fork` for these linkers. This makes each of these linkers slower by about 10%.

GNU ld is excluded from the benchmarks because its speed is so totally different to the other
linkers that it makes it hard to compare. But for reference, here is the time for GNU ld for this
benchmark:

```
Benchmark 1: GNU-ld-2.38
  Time (mean ± σ):      8.414 s ±  0.323 s    [User: 7.291 s, System: 1.121 s]
  Range (min … max):    7.601 s …  8.668 s    10 runs
```

Now with debug info:

```
❯ OUT=/home/david/ttt throttle-count hyperfine --warmup 1 -N -n lld-18 './run-with ld.lld' -n mold-2.36 './run-with mold --no-fork' -n wild-0.4.0 './run-with wild --no-fork'
temp: +42.0°C
Benchmark 1: lld-18
  Time (mean ± σ):     11.350 s ±  0.209 s    [User: 70.592 s, System: 6.677 s]
  Range (min … max):   11.085 s … 11.621 s    10 runs
 
Benchmark 2: mold-2.36
  Time (mean ± σ):     11.826 s ±  0.607 s    [User: 73.569 s, System: 5.435 s]
  Range (min … max):   11.130 s … 12.721 s    10 runs
 
Benchmark 3: wild-0.4.0
  Time (mean ± σ):      8.800 s ±  0.197 s    [User: 49.397 s, System: 8.273 s]
  Range (min … max):    8.588 s …  9.136 s    10 runs
 
Summary
  'wild-0.4.0' ran
    1.29 ± 0.04 times faster than 'lld-18'
    1.34 ± 0.08 times faster than 'mold-2.36'
Throttle pkg: 18454 core: 5916 ms: 328 temp: +77.0°C
```

Note, despite setting my fans to maximum before the start of the benchmark, I did get some thermal
throttling in this run. However, the standard deviations look pretty tight, so I don't think it
really invalidated the results.

The big takeaway from this benchmark is that debug info can make your link times really slow, so if
you don't need it, turn it off. If you do need it, try to use split debug info or unpacked debug
info. The situation with debug info is especially bad for C++ codebases like clang, probably due to
header files causing lots of the same information to be repeated.

### Linking rustc-driver.so on x86-64

Without debug info:

```
❯ OUT=/home/david/ttt throttle-count hyperfine --warmup 1 -N -n lld-18 './run-with ld.lld --strip-debug' -n mold-2.36 './run-with mold --no-fork --strip-debug' -n wild-0.4.0 './run-with wild --no-fork --strip-debug'
temp: +47.0°C
Benchmark 1: lld-18
  Time (mean ± σ):      1.485 s ±  0.009 s    [User: 2.247 s, System: 0.771 s]
  Range (min … max):    1.471 s …  1.499 s    10 runs
 
Benchmark 2: mold-2.36
  Time (mean ± σ):     819.9 ms ±   6.6 ms    [User: 3815.0 ms, System: 715.4 ms]
  Range (min … max):   810.3 ms … 829.3 ms    10 runs
 
Benchmark 3: wild-0.4.0
  Time (mean ± σ):     476.6 ms ±  46.6 ms    [User: 2080.9 ms, System: 514.6 ms]
  Range (min … max):   436.7 ms … 553.7 ms    10 runs
 
Summary
  'wild-0.4.0' ran
    1.72 ± 0.17 times faster than 'mold-2.36'
    3.12 ± 0.31 times faster than 'lld-18'
Throttle pkg: 0 core: 0 ms: 0 temp: +62.0°C
```

With debug info:

```
❯ OUT=/home/david/ttt throttle-count hyperfine --warmup 1 -N -n lld-18 './run-with ld.lld' -n mold-2.36 './run-with mold --no-fork' -n wild-0.4.0 './run-with wild --no-fork'
temp: +47.0°C
Benchmark 1: lld-18
  Time (mean ± σ):      1.663 s ±  0.022 s    [User: 3.244 s, System: 1.024 s]
  Range (min … max):    1.633 s …  1.710 s    10 runs
 
Benchmark 2: mold-2.36
  Time (mean ± σ):      1.120 s ±  0.016 s    [User: 5.126 s, System: 1.005 s]
  Range (min … max):    1.101 s …  1.149 s    10 runs
 
Benchmark 3: wild-0.4.0
  Time (mean ± σ):     646.3 ms ±  10.0 ms    [User: 3016.3 ms, System: 807.9 ms]
  Range (min … max):   626.0 ms … 657.5 ms    10 runs
 
Summary
  'wild-0.4.0' ran
    1.73 ± 0.04 times faster than 'mold-2.36'
    2.57 ± 0.05 times faster than 'lld-18'
Throttle pkg: 0 core: 0 ms: 0 temp: +62.0°C
```

### Linking clang on aarch64 (Raspberry Pi 5)

```
OUT=/run/user/1000/ttt hyperfine --warmup 2 -n lld-19 './run-with ld.lld-19 --strip-debug' -n mold-2.36 './run-with mold --no-fork --strip-debug' -n wild-0.4.0 './run-with wild --no-fork --strip-debug'
Benchmark 1: lld-19
  Time (mean ± σ):      1.170 s ±  0.005 s    [User: 2.046 s, System: 0.233 s]
  Range (min … max):    1.165 s …  1.177 s    10 runs
 
Benchmark 2: mold-2.36
  Time (mean ± σ):     919.3 ms ±   2.7 ms    [User: 3120.7 ms, System: 304.4 ms]
  Range (min … max):   915.5 ms … 923.7 ms    10 runs
 
Benchmark 3: wild-0.4.0
  Time (mean ± σ):     423.1 ms ±   5.5 ms    [User: 1352.9 ms, System: 147.1 ms]
  Range (min … max):   419.1 ms … 438.0 ms    10 runs
 
Summary
  wild-0.4.0 ran
    2.17 ± 0.03 times faster than mold-2.36
    2.76 ± 0.04 times faster than lld-19
```

### Linking wild on aarch64 (Raspberry Pi 5)

Without debug info:

```
OUT=/run/user/1000/ttt hyperfine -N --warmup 2 -n lld-19 './run-with ld.lld-19 --strip-debug' -n mold-2.36 './run-with mold --no-fork --strip-debug' -n wild-0.4.0 './run-with wild --no-fork --strip-debug'
Benchmark 1: lld-19
  Time (mean ± σ):     225.7 ms ±   2.6 ms    [User: 321.5 ms, System: 52.5 ms]
  Range (min … max):   222.8 ms … 232.7 ms    13 runs
 
Benchmark 2: mold-2.36
  Time (mean ± σ):     152.2 ms ±   0.7 ms    [User: 496.0 ms, System: 46.8 ms]
  Range (min … max):   150.5 ms … 153.5 ms    19 runs
 
Benchmark 3: wild-0.4.0
  Time (mean ± σ):      78.3 ms ±   0.8 ms    [User: 227.9 ms, System: 30.6 ms]
  Range (min … max):    76.9 ms …  80.3 ms    38 runs
 
Summary
  wild-0.4.0 ran
    1.94 ± 0.02 times faster than mold-2.36
    2.88 ± 0.04 times faster than lld-19
```

With debug info:

```
OUT=/run/user/1000/ttt hyperfine --warmup 2 -n lld-19 './run-with ld.lld-19' -n mold-2.36 './run-with mold --no-fork' -n wild-0.4.0 './run-with wild --no-fork'
Benchmark 1: lld-19
  Time (mean ± σ):     325.0 ms ±   4.5 ms    [User: 664.0 ms, System: 66.3 ms]
  Range (min … max):   319.2 ms … 333.7 ms    10 runs
 
Benchmark 2: mold-2.36
  Time (mean ± σ):     262.3 ms ±   2.7 ms    [User: 890.9 ms, System: 75.3 ms]
  Range (min … max):   259.1 ms … 269.6 ms    11 runs
 
Benchmark 3: wild-0.4.0
  Time (mean ± σ):     183.2 ms ±   3.1 ms    [User: 588.5 ms, System: 64.5 ms]
  Range (min … max):   179.8 ms … 192.3 ms    16 runs
 
Summary
  wild-0.4.0 ran
    1.43 ± 0.03 times faster than mold-2.36
    1.77 ± 0.04 times faster than lld-19
```

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
