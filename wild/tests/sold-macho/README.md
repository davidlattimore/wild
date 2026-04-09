# sold Mach-O Test Suite

Tests adapted from the [sold](https://github.com/bluewhalesystems/sold)
Mach-O linker by Rui Ueyama (Blue Whale Systems).

## Source

<https://github.com/bluewhalesystems/sold/tree/main/test/macho>

## License

MIT License (Copyright 2023 Rui Ueyama) -- see [LICENSE.md](LICENSE.md).

## Format

Each test is a bash script that:

1. Compiles C/C++ source via heredocs using `$CC`
2. Links with `$CC --ld-path=./ld64` (the test runner symlinks Wild as `ld64`)
3. Runs the output binary and verifies behavior (usually via `grep -q`)

The `common.inc` file sets up `$CC`, `$CXX`, trap handlers, and `$t` (temp dir).

## Running

```sh
cargo test --test sold_macho_tests
```

## Note

The sold repository is archived and no longer maintained. This is a
complete snapshot of its Mach-O test suite as of the final commit.
