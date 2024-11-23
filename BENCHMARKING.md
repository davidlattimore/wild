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

### Run benchmark with hyperfine

* To benchmark, you can then run something
  like "`hyperfine --warmup 2 '/tmp/wild/ripgrep/6/run-with ld' '/tmp/wild/ripgrep/6/run-with mold'
  '/tmp/wild/ripgrep/6/run-with wild'`"
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

### Run benchmark with poop

An alternative tool to hyperfine, that reports some additional metrics is [`poop`](https://github.com/andrewrk/poop).

Like hyperfine it takes a number of commands and runs each a number of times and gathers statistics about each tune.

Run it using `poop '/tmp/wild/ripgrep/6/run-with ld' '/tmp/wild/ripgrep/6/run-with mold'
'/tmp/wild/ripgrep/6/run-with wild'`

It should produce output similar to this (with different numbers!):

```text
Benchmark 1 (6 runs): /tmp/wild/ripgrep/6/run-with ld
measurement          mean ± σ min …     max outliers delta
wall_time           911ms ± 20.9ms      897ms … 952ms 0 ( 0%)        0%
peak_rss            282MB ± 94.3KB      282MB … 282MB 0 ( 0%)        0%
cpu_cycles          2.24G ± 11.2M       2.22G … 2.25G 0 ( 0%)        0%
instructions        3.78G ± 8.64K       3.78G … 3.78G 0 ( 0%)        0%
cache_references    92.2M ± 319K        91.8M … 92.6M 0 ( 0%)        0%
cache_misses        38.2M ± 428K        37.8M … 38.8M 0 ( 0%)        0%
branch_misses       9.27M ± 16.7K       9.24M … 9.29M 0 ( 0%)        0%

Benchmark 2 (31 runs): /tmp/wild/ripgrep/6/run-with mold
measurement          mean ± σ min …     max outliers delta
wall_time           163ms ± 36.9ms      149ms … 356ms 2 ( 6%)       ⚡- 82.1% ± 3.5%
peak_rss           7.88MB ± 81.1KB     7.73MB … 8.00MB 0 ( 0%)      ⚡- 97.2% ± 0.0%
cpu_cycles          1.93G ± 20.9M       1.89G … 1.96G 0 ( 0%)       ⚡- 13.6% ± 0.8%
instructions        1.95G ± 1.30M       1.95G … 1.95G 1 ( 3%)       ⚡- 48.4% ± 0.0%
cache_references    43.3M ± 260K        43.0M … 44.3M 1 ( 3%)       ⚡- 53.0% ± 0.3%
cache_misses        20.6M ± 134K        20.4M … 21.1M 1 ( 3%)       ⚡- 46.1% ± 0.5%
branch_misses       7.12M ± 42.0K       7.02M … 7.19M 0 ( 0%)       ⚡- 23.2% ± 0.4%

Benchmark 3 (50 runs): /tmp/wild/ripgrep/6/run-with wild
measurement          mean ± σ min …     max outliers delta
wall_time           101ms ± 3.10ms     95.2ms … 109ms 1 ( 2%)       ⚡- 88.9% ± 0.7%
peak_rss            235MB ± 200KB       234MB … 235MB 1 ( 2%)       ⚡- 16.8% ± 0.1%
cpu_cycles          1.24G ± 15.6M       1.19G … 1.27G 3 ( 6%)       ⚡- 44.4% ± 0.6%
instructions        1.21G ± 443K        1.21G … 1.21G 0 ( 0%)       ⚡- 67.9% ± 0.0%
cache_references    34.0M ± 505K        33.1M … 35.0M 0 ( 0%)       ⚡- 63.1% ± 0.5%
cache_misses        14.2M ± 171K        13.9M … 14.5M 0 ( 0%)       ⚡- 62.9% ± 0.5%
branch_misses       3.42M ± 11.0K       3.40M … 3.45M 0 ( 0%)       ⚡- 63.1% ± 0.1%
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
