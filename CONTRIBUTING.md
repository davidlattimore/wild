# Contributing to wild

If you'd like to help out, we'd love to hear from you. It's a good idea to reach out first to avoid
duplication of effort. Also, it'll make it possible for us to provide hints that might make what
you're trying to do easier.

## Options for communicating

Feel free to start a [discussion](https://github.com/davidlattimore/wild/discussions) or open an
[issue](https://github.com/davidlattimore/wild/issues).

You're also welcome to reach out directly to the following people:

* [David Lattimore](https://davidlattimore.github.io/about/) - original author and primary
  maintainer. I love talking about this stuff, so feel free to set up a video call to discuss.
  You're also welcome to PM me on the [rust-lang zulip](https://rust-lang.zulipchat.com/).

## Ways you can contribute

* Use `wild` and let us know your experiences, or file issues for problems found.
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

## Running aarch64 tests on x86_64

Some, but currently not all, of the tests that run on aarch64 can be run on x86_64.

Setup procedure:

* `rustup target add --toolchain nightly aarch64-unknown-linux-gnu aarch64-unknown-linux-musl`
* For apt-based systems:
  * `sudo apt install qemu-user gcc-aarch64-linux-gnu g++-aarch64-linux-gnu binutils-aarch64-linux-gnu build-essential`

Then when running tests:

```sh
WILD_TEST_CROSS=aarch64 cargo test
```

This will run both the host-native tests (x86_64) as well as many of the same tests, but on aarch64.
Qemu is used for running the binaries produced by the linker. All compilation, linking and diffing
however is done natively on the host system, so should run at full speed.

Cross compilation is currently only done with GCC and rustc, so clang-based tests currently all
disable cross compilation.

Cross compilation is set up in docker/debian.Dockerfile.

## Configuration file for tests

Currently, the behavior for the following test options can be configured using the TOML format:

- `rustc_channel`: Specifies which Rust compiler channel to use when running tests that build Rust code. The default value is "default", which means no explicit toolchain is specified.

- `use_qemu`: Determines whether to run tests for architectures different from the host. This setting is overridden by the `$WILD_TEST_CROSS` environment variable. The default value is `false`.

- `allow_rust_musl_target`: Specifies whether to allow the musl target Rust. The default value is `false`, so you’ll need to set it to `true` if you want to run tests targeting musl.

A sample configuration file is provided as `test-config.toml.sample`.
By default, Wild uses `test-config.toml` as the configuration file.
If you have written your configuration in a different file, specify its location using the `WILD_TEST_CONFIG` environment variable as follows:

```sh
WILD_TEST_CONFIG=path_to_config cargo test
```

## GitHub workflow

TL;DR: We're pretty relaxed. Feel free to force push or not. Squash, rebase, merge, whatever you
like, we'll find ways to work with it.

In order to make things like `git bisect` easier, this project maintains a linear sequence of
commits. So PRs get rebased and we don't use merge commits.

It's fine for you to use whatever workflow you like when making a PR. For example, if you want to
add fix-up commits as the PR progresses, that's fine. We'll squash the PR when merging. It's also
fine to amend commits as you go.

When merging, if it looks like your commits are intended to be merged separately, we'll rebase
without squashing. If you'd like your commits not to be squashed, then please mention this on the PR
to save us needing to guess.

If you end up with merge commits in your PR, that's OK, but we'll definitely need to squash the
commits when merging.

Feel free to mark your PR as a draft at any stage if you know there's more you'd like to do with it
and want to avoid us merging it before it's ready.

## Coding style

This is mostly handled by rustfmt. A couple of the format options that we use aren't yet stable, so
you'll need to format with nightly. Before you upload your PR, you should run the following:

```sh
cargo +nightly fmt
```

### One import per line

One style thing that might be slightly different is that we use one import per line. i.e. we don't
use `{}` in `use` statements. This has two benefits. Firstly, merge conflicts are significantly less
likely. Secondly, if a merge conflict does happen, it's significantly easier to resolve. The
downside is that it's more verbose, but since your IDE is probably adding these lines for you
anyway, it shouldn't matter.

### Panic policy

Panicking if there's a bug is OK. It's generally better to crash in a way that's easy to tell what
happened rather than produce an invalid executable. That said, lots of the code, when it detects an
inconsistent internal state (a bug), returns an error rather than panicking. The reason for this is
not to avoid the panic per se, but rather because by returning an error, we can attach more
contextual information to the error to help diagnose the problem. For example, we can add
information about what symbol we were processing and which input file we were looking at. This is
usually more useful for us than a stack trace showing where it was in the code. Also, since Wild is
very multi-threaded, if there's a bug that causes all the threads to panic, the output can get
pretty messed up.

So in summary, if you think something shouldn't happen, it's fine to panic. Calling `unwrap` is
fine. But if you're less sure that it can't happen, or you've observed it happen and need to debug
why it happened, then switching to returning an error is recommended.

## Building wild with wild

You can add or modify a `.cargo/config.toml` file to change the linker used to build `wild` to be `wild`!

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
[Hierarchical structure](https://doc.rust-lang.org/cargo/reference/config.html) that `cargo` uses to determine config.

## Reading

Linkers are complex bits of software. Here are some resources that are good for learning what
linkers need to do.

* [Ian Lance Taylor's blog post series](https://lwn.net/Articles/276782/). Ian wrote the GNU Gold
  linker. This series is a bit old now, so doesn't have some more recent stuff, but is nonetheless a
  great introduction.
* [Maskray's blog](https://maskray.me/blog/). Maskray maintains the LLD linker and has many awesome
  blog posts about various linker-related topics. A few posts in particular:
  * [All about thread-local storage](https://maskray.me/blog/2021-02-14-all-about-thread-local-storage)
  * [All about Global Offset Table](https://maskray.me/blog/2021-08-29-all-about-global-offset-table)
  * [Copy relocations, canonical PLT entries and protected
    visibility](https://maskray.me/blog/2021-01-09-copy-relocations-canonical-plt-entries-and-protected)
  * [All about COMMON symbols](https://maskray.me/blog/2022-02-06-all-about-common-symbols). Despite
    their name, common symbols aren't commonly used. They are however used in libc, so are necessary
    if you want to be able to link pretty much anything.
  * Everything else with the [linker tag](https://maskray.me/blog/tags/linker/)
* For Wild specific content, there's [David Lattimore's](https://davidlattimore.github.io/) blog.
* There are also various specification documents. These may not be the best to read start-to-finish,
  but can be good when you need some specific details on something.
  * [ELF-64 Object File Format](https://uclibc.org/docs/elf-64-gen.pdf)
  * [ELF x86-64-ABI psABI](https://gitlab.com/x86-psABIs/x86-64-ABI)
  * [ELF Handling For Thread-Local Storage](https://www.uclibc.org/docs/tls.pdf)
  * [ELF for the Arm® 64-bit Architecture (AArch64)](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst)
  * [System V ABI for the Arm® 64-bit Architecture (AArch64)](https://github.com/ARM-software/abi-aa/blob/main/sysvabi64/sysvabi64.rst)
* [A Deep dive into (implicit) Thread Local Storage](https://chao-tic.github.io/blog/2018/12/25/tls)

## Finding an issue to work on

* Whatever issue you work on, please comment on the issue to let us know you're working on it,
  otherwise two people might end up working on the same issue and that could be disappointing if
  someone then felt like they'd wasted their time. It's perfectly OK to say that you're going to
  work on something, then later realise that it's not for you.
* If you'd like to work on something that someone said they're working on, but they haven't provided
  an update in a while, feel free to politely ask if they're still working on it and mention that if
  they're not, you'd like to have a go.
* We may on occasion tag issues as [good first
  issue](https://github.com/davidlattimore/wild/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).
  One person's good-first-issue might be too hard or too easy for another person, so this is a
  somewhat hard judgement to make.
* You're welcome to help out with other unassigned issues too, even if they don't have tags. If
  you're interested in possibly working on such an issue, comment on it and we'll see what guidance
  we can provide. This will also allow us to assign the issue to you so that other's don't duplicate
  efforts.
