# Releasing wild

* Add release notes to `CHANGELOG.md`. The header for the release must be just the version number
  that is going to be released.
* Change version in `Cargo.toml`
* Ensure that the above changes are merged into the main repository.
* Run `cargo publish` for each package.
* Trigger the github release action by pushing a tag for the version number.

```shell
git tag 0.6.0 # Where "0.6.0" is the number in Cargo.toml 
git push origin refs/tags/0.6.0
```

That should trigger the `release.yml` workflow in GitHub. You can follow its progress in the
[Actions tab](https://github.com/davidlattimore/wild/actions) in GitHub.

When complete, it should create the release in [Releases](https://github.com/davidlattimore/wild/releases).

Maintainers can then edit the release notes associated with the release.

If everything looks good, publish the release.
