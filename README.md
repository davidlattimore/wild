# Wild linker

Wild is a linker with the goal of being very fast for iterative development.

It's still very much a work-in-progress and definitely shouldn't be used for linking any production
binaries. It's probably not really ready for development purposes yet, since there's a bunch of
important stuff it can't yet do like debug info and dynamic linking.

## Q&A

### Why another linker?

Mold is already very fast, however it doesn't do incremental linking and the author has stated that
they don't intend to. Wild doesn't do incremental linking yet, but that is the end-goal. By writing
Wild in Rust, it's hoped that the complexity of incremental linking will be achievable.

### What isn't yet supported?

Lots of stuff. Here are some of the larger things that aren't yet done, roughly sorted by current
priority:

* Debug info
* Support for position-independent static executables
* Dynamic linking
* Incremental linking
* Mac support
* Windows support
* Support for a wider range of linker flags
* Linker scripts
* LTO

### Where did the name come from?

It's somewhat of a tradition for linkers to end with the letters "ld". e.g. "GNU ld, "gold", "lld",
"mold". Since the end-goal is for the linker to be incremental, an "I" is added. The "W" doesn't
stand for anything and was just selected based on it giving an interesting word.

### Benchmarks

Until recently, eh_frames (needed for unwinding) weren't supported, which meant that a fair
comparison wasn't possible. Now that eh_frames support has been implemented, benchmarking could
possibly be done, but hasn't yet.

## Linking Rust code

Currently Wild only works with somewhat specific compilation and linking options. The following is a
`cargo test` command-line that can be used to build and test a crate using Wild. This has been run
successfully on a few popular crates (e.g. ripgrep, serde). It assumes that the "wild" binary is on
your path.

```sh
cargo test --target x86_64-unknown-linux-musl --config 'target.x86_64-unknown-linux-musl.linker="/usr/bin/clang-15"' --config 'target.x86_64-unknown-linux-musl.rustflags="-C relocation-model=static -C target-feature=+crt-static -C debuginfo=0 -C link-arg=--ld-path=wild"'
```

### Filing issues / contributing

There are lots of known things that aren't yet implemented, so for now, I'd ask that you not file
issues like "Crate X does Y when linked with Wild". The time to investigate such issues is probably
better spent implementing known missing features.

If you'd like to work on something specific, please reach out either by filing an issue or via email
so that we can avoid any wasted work. For synchronous communication, I like video chat, so if you'd
like to discuss Wild by video chat, do let me know. Usually I just use Google Meet, but open to
other options. I'm in Sydney - GMT+10 or GMT+11.

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
