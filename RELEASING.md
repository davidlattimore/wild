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

## Generating a release

With that setup, generating a release is as simple as pushing a tag on the `main` branch, for the release.

Example:

```shell
git tag 0.1.0
git push --tags
```

That should trigger the `release.yml` workflow in GitHub. You can follow its progress in the
[Actions tab](https://github.com/davidlattimore/wild/actions) in GitHub.

When complete, it should create the release in [Releases](https://github.com/davidlattimore/wild/releases).

Maintainers can then edit the release notes associated with the release.