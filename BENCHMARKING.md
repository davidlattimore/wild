# Benchmarking Wild

## Benchmarking against other linkers

If you decide to benchmark Wild against other linkers, in order to make it a fair comparison, you
should ensure that the other linkers aren't doing work on something that Wild doesn't support. In
particular:

* Wild defaults to `--gc-sections`, so for a fair comparison, that should be passed to all the linkers.
* Wild defaults to `-z now`, so best to pass that to all linkers.

There might be other flags that speed up the other linkers by letting them avoid some work that
they're currently doing. If you know of such flags, please let me know.

## How to benchmark

For benchmarking the linker, it's preferable to run just the linker, not the whole build process.

The way to do that is by capturing the linker invocation so that it can be rerun. Wild has a built-in way to do that.

TODO: Is it best to benchmark a debug or a release build? or both for different reasons?

Follow-these steps:

* Chose the crate that you wish to use in your benchmark, clone it, `cd` into it's root directory and make sure it
  builds with `cargo build` (for a rust project)
    * Examples: [`ripgrep`](https://github.com/BurntSushi/ripgrep.git)
* Clean the build using `cargo clean`
* Set `RUSTFLAGS` or modify `.cargo/config.toml` to have the build use wild
    * `RUSTFLAGS`:
    * `.cargo/config.toml`: add this (example for `ripgrep`)

```toml
  [target.x86_64-unknown-linux-gnu]
linker = "/usr/bin/clang"

rustflags = [
    "-C", "relocation-model=static",
    "-C", "link-arg=--ld-path=wild"
]
```

* Make sure that you have a version of wild in your `$PATH` so that it will be used
* Run `WILD_SAVE_BASE=/tmp/wild/ripgrep cargo build` in the crate's root directory
* You will get a few numbered subdirectories in `/tmp/wild/ripgrep`
* The last numbered subdirectory will be the final link stage of the binary (TODO clarify that)
* In the case of ripgrep it is '6'
* You can then run `/tmp/wild/ripgrep/6/run-with wild` and that will rerun the link with wild
* To benchmark, you can then run something
  like `hyperfine --warmup 2 '/tmp/wild/ripgrep/6/run-with ld' '/tmp/wild/ripgrep/6/run-with mold' '
  /tmp/wild/ripgrep/6/run-with wild'`
    * This will benchmark the linking stage between `ld`, `mold` and `wild`, discarding the first two runs of each to
      reduce the effects of cache warmup

That should produce output similar to this (with different values):

```text
Benchmark 1: /tmp/wild/ripgrep/6/run-with ld
  Time (mean ± σ):     931.0 ms ±   7.2 ms    [User: 680.8 ms, System: 249.1 ms]
  Range (min … max):   923.1 ms … 944.6 ms    10 runs
 
Benchmark 2: /tmp/wild/ripgrep/6/run-with mold
  Time (mean ± σ):     144.3 ms ±   6.1 ms    [User: 53.2 ms, System: 1.7 ms]
  Range (min … max):   133.0 ms … 156.4 ms    18 runs
 
Benchmark 3: 
  /tmp/wild/ripgrep/6/run-with wild
  Time (mean ± σ):     101.9 ms ±   5.0 ms    [User: 389.8 ms, System: 135.4 ms]
  Range (min … max):    95.3 ms … 118.4 ms    30 runs
 
Summary
  
  /tmp/wild/ripgrep/6/run-with wild ran
    1.42 ± 0.09 times faster than /tmp/wild/ripgrep/6/run-with mold
    9.14 ± 0.46 times faster than /tmp/wild/ripgrep/6/run-with ld
```

### Comparisons

Using this method, you can benchmark:

* between Wild and one or more other linkers
* between different options passed to Wild - You can pass arbitrary additional arguments to run-with.
  The first argument needs to be the name of the linker to use. All additional arguments are passed through to the
  linker as-is

### Caching

The use of CPU caches affects linker performance, for that reason, when running hyperfine we use the `--warmup 2`
option: so that the first two runs (before caches are used) get discarded.

TODO: When users are running their build, it's not clear that the cache could be filled from a previous run and
taken advantage of, so it may be interesting to compare the first runs (without cache from a previous run)
separately. However, to do so, we would need to ensure that caches are invalidated and re-run the first run a
number of times to get reliable results.

## What to benchmark

### rustc - TODO document this

Build rustc as per the instructions on the rustc-dev-guide, but with a hack to make it use wild instead of another
linker.

### Other tools

* [poop](https://github.com/andrewrk/poop) - gives a lot of measurements other than just time

## Unknowns and future work

Many unknowns remain and I want to improve the benchmarking of wild over time, to reduce them, or
to quantify them as feature set grows and wild (and other linkers) evolve over time

* Will the results be significantly different between linkers depending on the packages being linked?
* How will Wild perform when linking much larger binaries.
* How will Wild scale when running on systems with many CPU cores?
* Will implementing the missing features require changes to Wild's design slow it down?

## Profiling

We will add documentation on how to gather profile information when running Wild, whether in a benchmark or manually.
