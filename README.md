# Wild linker

Wild is a linker with the goal of being very fast for iterative development.

It's still very much a work-in-progress and definitely shouldn't be used for linking any production
binaries.

## Q&A

### Why another linker?

Mold is already very fast, however it doesn't do incremental linking and the author has stated that
they don't intend to. Wild doesn't do incremental linking yet, but that is the end-goal. By writing
Wild in Rust, it's hoped that the complexity of incremental linking will be achievable.

### What's working?

The following platforms / architectures are currently supported:

* x86-64 on Linux

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
* Support for architectures other than x86-64
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
strings my-executable | grep Linker
```

### Where did the name come from?

It's somewhat of a tradition for linkers to end with the letters "ld". e.g. "GNU ld, "gold", "lld",
"mold". Since the end-goal is for the linker to be incremental, an "I" is added. Let's say the "W"
stands for "Wild", since recursive acronyms are popular in open-source projects.

### Benchmarks

There are lots of features that Wild doesn't yet support, so I'm not sure benchmarking is super
useful at this stage. That said, I have done some very preliminary comparisons. I've tried linking
the binary in my [warm build benchmark
repository](https://github.com/davidlattimore/warm-build-benchmark), which builds an ~80MB, non-PIE,
statically linked binary with symbol tables, eh-frames and no debug info. On my laptop, I get the
following times:

| Linker   | Time (ms) | ± Standard deviation (ms) | CPU time (ms) | File size (MiB)
|----------|-----------|---------------------------|---------------|----------------
| GNU ld   | 12300     | 150                       | 12299         | 80.3
| gold     | 3365      | 30                        | 3362          | 83.3
| lld      | 905       | 5.6                       | 1222          | 84.8
| mold     | 457       | 7.2                       | 2834          | 81.1
| wild     | 363       | 6.6                       | 1585          | 80.9

Notes about these results:
* CPU time is user + system CPU time as reported by hyperfine.
* Mold by default forks, which lets the user not wait for the mold process that does the work to
  shutdown. This is a neat optimisation. In the above benchmarks, the time column is with this
  optimisation enabled. The CPU time however is with this optimisation disabled (--no-fork), since
  when forking is enabled, we can't easily measure the CPU time.

I want to stress that this is only one benchmark. Many unknowns remain:

* Will the results be significantly different for other benchmarks?
* How will Wild scale up when linking much larger binaries and/or on systems with many CPU cores?
* Will implementing the missing features require changes to Wild's design that might slow it down?

All we can really conclude from this benchmark is that Wild is currently reasonably efficient at
non-incremental linking and reasonable at taking advantage of a few threads. I don't think that
adding the missing features should change this benchmark significantly. i.e. adding support for
debug info really shouldn't change our speed when linking with no debug info. I can't be sure
however until I implement these missing features.

If you decide to benchmark Wild against other linkers, in order to make it a fair comparison, you
should ensure that the other linkers aren't doing work on something that Wild doesn't support. In
particular:

* Wild always does `--gc-sections`, so for a fair comparison, that should be passed to all the
  linkers.
* Wild defaults to `-z now`, so best to pass that to all linkers.

There might be other flags that speed up the other linkers by letting them avoid some work that
they're currently doing. If you know of such flags, please let me know.

## Linking Rust code

The following is a `cargo test` command-line that can be used to build and test a crate using Wild.
This has been run successfully on a few popular crates (e.g. ripgrep, serde, tokio, rand, bitflags).
It assumes that the "wild" binary is on your path. It also depends on the Clang compiler being
installed, since GCC doesn't allow using an arbitrary linker.

```sh
RUSTFLAGS="-Clinker=clang -Clink-args=--ld-path=wild" cargo test
```

### Contributing

If you'd like to help out, I'd love to hear from you. It's a good idea to reach out first to avoid
duplication of effort. Also, it'll make it possible for me to provide hints that might make what
you're trying to do easier. Options for communicating:

* I like, where possible, to talk to people video video chat. You can book a time in my
  [calendar](https://calendar.app.google/MBYQeATMNBvuK8AZ6). If time zones make this hard, let me
  know via some other means and I'll see if we can find a time that works (I'm in Sydney,
  Australia).
* Open an issue or a discussion here on github.
* Message me on the [rust-lang Zulip](https://rust-lang.zulipchat.com/)
* Email me at dvdlttmr@gmail.com

### Sponsorship

If you'd like to [sponsor this work](https://github.com/sponsors/davidlattimore), that would be very
much appreciated. The more sponsorship I get the longer I can continue to work on this project full
time.

### License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
Wild by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
