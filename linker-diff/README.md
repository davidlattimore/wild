# linker-diff

Linker-diff is a command-line utility that diffs two ELF binaries (shared objects or executables).
At least one of the binaries being diffed needs layout information as can optionally be produced by
the Wild linker.

## Usage

The easiest way to use linker-diff is to first make sure it's installed into the same directory as
the wild linker, then build with the environment variable `WILD_REFERENCE_LINKER` set to the name of
another linker. e.g.

```sh
WILD_REFERENCE_LINKER=ld cargo test
```

When this variable is set, each time the wild linker is invoked, it'll call the specified linker
then run linker-diff on the result.
