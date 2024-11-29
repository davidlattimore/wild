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

## Github workflow

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
