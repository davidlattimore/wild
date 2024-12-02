# Releasing wild

Releases are automated using `cargo-dist`.

## First time or on changes in release structure

It can be installed with either `cargo install cargo-dist` or `cargo binstall cargo-dist` (if you have cargo binstall
installed).

To init, or refresh the `cargo-dist` generated files (`dist-workspace.toml` and `.github/workflows/release.yml`) use:

```shell
dist init
```

This will ask you a series of questions about the targets you want to build, and installers you want to create and
will then generate or update the mentioned files.

Then commit and push those files, merging a PR if necessary, so those files are in the `main` branch.

## Crate version and Release numbering

You probably want the version number of the crate to match the version number of the release!

In that case you will want to modify the version number in [`wild/Cargo.toml`](wild/Cargo.toml).

## Generating a release

With that setup, generating a release is as simple as pushing a tag on the `main` branch, for the release.

Example:

```shell
git tag 0.2.0 # Where "0.2.0" is the number in wild/Cargo.toml 
git push --tags
```

That should trigger the `release.yml` workflow in GitHub. You can follow its progress in the
[Actions tab](https://github.com/davidlattimore/wild/actions) in GitHub.

When complete, it should create the release in [Releases](https://github.com/davidlattimore/wild/releases).

Maintainers can then edit the release notes associated with the release.

## Crates.io

You can optionally decide to also distribute wild in source form via [crates.io](https://crates.io/) using

```shell
cargo publish
```

NOTE: This will require a name change or publishing under a different name as there is a crate already published
with the name `wild`
