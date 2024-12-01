# Contributing to wild

If you'd like to help out, I'd love to hear from you. It's a good idea to reach out first to avoid duplication of
effort. Also, it'll make it possible for me to provide hints that might make what you're trying to do easier.

## Options for communicating

* I like, where possible, to talk to people via video chat.
* You can book a time in my [calendar](https://calendar.app.google/MBYQeATMNBvuK8AZ6). If time zones make this hard, let
  me know via some other means, and I'll
  see if we can find a time that works (I'm in Sydney, Australia).
* Message me on the [rust-lang Zulip](https://rust-lang.zulipchat.com/)
* Email me at dvdlttmr@gmail.com

## Ways you can contribute

* Use `wild` and let me know your experiences, or file issues for problems found.
* Open an issue or a discussion here on GitHub.
* Sending a PR related to some issue

## Running tests

To run tests (and have them pass) there are a number of pre-requisites to have installed on Linux:

* `clang` 'C' compiler
* `lld` linker
* `nightly-x86_64-unknown-linux-gnu` toolchain (add with `rustup install nightly-x86_64-unknown-linux-gnu`)
* `x86_64-unknown-linux-musl` target for the nightly toolchain (add
  with `rustup target add --toolchain nightly x86_64-unknown-linux-musl`)
* cranelift backend (add with `rustup component add rustc-codegen-cranelift-preview --toolchain nightly`)

then use `cargo test` as usual.

## Building wild with wild

You can add or modify a `.cargo/config.toml` file to change the linked used to build `wild` to be `wild`!

The below example has entries for `musl` and `gnu` ABI targets:

```toml
[target.x86_64-unknown-linux-musl]
linker = "/usr/bin/clang"
rustflags = ["-C", "relocation-model=static", "-C", "link-arg=--ld-path=wild"]

[target.x86_64-unknown-linux-gnu]
linker = "/usr/bin/clang"
rustflags = ["-C", "link-arg=--ld-path=wild"]
```

The `.cargo/config.toml` file can be added in the root folder of the project, or somewhere else according to the
[Hierarchical structure](https://doc.rust-lang.org/cargo/reference/config.html) that `cargo` uses to determine config