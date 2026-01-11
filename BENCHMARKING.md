# Benchmarking Wild

## Benchmarking against other linkers

If you decide to benchmark Wild against other linkers, in order to make it a fair comparison, you
should ensure that the other linkers aren't doing work on something that Wild doesn't support. In
particular:

* Wild defaults to `--gc-sections`, so for a fair comparison, that should be passed to all the linkers.
* Wild defaults to `-z now`, so best to pass that to all linkers.
* Wild doesn't support linker plugins and various other flags. Generally use of these flags will
  result in a warning.

## How to benchmark

### Preparing the "run-with" files

For benchmarking the linker, it's preferable to run just the linker, not the whole build process.

The way to do that is by capturing the linker invocation so that it can be rerun. Wild has a
built-in way to do that.

You can benchmark linking of either a debug or a release build of a crate, this depends on what
comparisons you wish to make, or what change in wild you want to quantify.

Follow-these steps:

* Chose the crate that you wish to use in your benchmark, clone it, `cd` into it's root directory
  and make sure it builds with `cargo build` (for a rust project)
    * Examples: [`ripgrep`](https://github.com/BurntSushi/ripgrep.git)
* Clean the build using `cargo clean`
* To force the build of your chosen crate to link using wild, we have a couple of options:
    * Prefix the cargo build command with `RUSTFLAGS="-Clinker=clang -Clink-arg=--ld-path=wild"`
    * Modify (or add) the `.cargo/config.toml` file in your chosen crate (example for `ripgrep`)

```toml
[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-Clink-arg=--ld-path=wild"]
```

* Make sure that you have a version of wild in your `$PATH` so that it will be used (try `which
  wild` to check)
* Run `WILD_SAVE_BASE=/tmp/wild/ripgrep cargo build` in the crate's root directory (include
  `RUSTFLAGS` as above if you have chosen that method)
* You will get a few numbered subdirectories in `/tmp/wild/ripgrep` as part of the build process.
    * Directories will be created for builds of build scripts, proc macros and crate binaries built
    * Usually the last numbered subdirectory will be the build of crate's binary (if a single binary
      is built)
    * You can check what each file is linking using `tail -n 1 /tmp/wild/ripgrep/*/run-with`
    * In the case of ripgrep it is '6'
* You can then run `/tmp/wild/ripgrep/6/run-with wild` and that will rerun the link with wild

When you run `run-with wild`, the linker may print warnings for unsupported flags. It's a good idea
to edit the `run-with` script to change / delete these flags. This will make comparison with other
linkers more fair, since some of these unsupported flags may involve other linkers doing significant
amounts of extra work.

### Run benchmark with hyperfine

Let's benchmark the linking stage between `ld`, `mold` and `wild`, discarding the first two runs of
each to reduce the effects of cache warmup

```shell
hyperfine --warmup 2 '/tmp/wild/ripgrep/6/run-with ld' '/tmp/wild/ripgrep/6/run-with mold' '/tmp/wild/ripgrep/6/run-with wild'
```

That should produce output similar to this (with different values):

```text
Benchmark 1: /tmp/wild/ripgrep/6/run-with ld
  Time (mean ± σ):     954.1 ms ±  13.6 ms    [User: 683.4 ms, System: 268.8 ms]
  Range (min … max):   920.6 ms … 970.7 ms    10 runs
 
Benchmark 2: /tmp/wild/ripgrep/6/run-with mold
  Time (mean ± σ):     146.1 ms ±   3.6 ms    [User: 52.0 ms, System: 2.4 ms]
  Range (min … max):   139.1 ms … 154.7 ms    19 runs
 
Benchmark 3: /tmp/wild/ripgrep/6/run-with wild
  Time (mean ± σ):      87.7 ms ±   2.8 ms    [User: 2.4 ms, System: 2.0 ms]
  Range (min … max):    81.5 ms …  92.5 ms    34 runs
 
Summary
  /tmp/wild/ripgrep/6/run-with wild ran
    1.67 ± 0.07 times faster than /tmp/wild/ripgrep/6/run-with mold
   10.88 ± 0.38 times faster than /tmp/wild/ripgrep/6/run-with ld
```

### Run benchmark with poop

An alternative tool to hyperfine, that reports some additional metrics is [`poop`](https://github.com/andrewrk/poop).

Like hyperfine it takes a number of commands and runs each a number of times and gathers statistics about each tune.

```shell
poop '/tmp/wild/ripgrep/6/run-with ld' '/tmp/wild/ripgrep/6/run-with mold' '/tmp/wild/ripgrep/6/run-with wild'
```

It should produce output similar to this (with different numbers!):

```text
Benchmark 1 (5 runs): /tmp/wild/ripgrep/6/run-with ld
  measurement          mean ± σ            min … max           outliers         delta
  wall_time          1.18s  ±  335ms     926ms … 1.68s           0 ( 0%)        0%
  peak_rss            288MB ±  276KB     287MB …  288MB          1 (20%)        0%
  cpu_cycles         2.51G  ±  341M     2.28G  … 3.06G           0 ( 0%)        0%
  instructions       3.93G  ± 9.54K     3.93G  … 3.93G           0 ( 0%)        0%
  cache_references   98.7M  ± 2.59M     96.4M  …  102M           0 ( 0%)        0%
  cache_misses       41.9M  ± 2.52M     40.3M  … 46.3M           0 ( 0%)        0%
  branch_misses      9.77M  ±  223K     9.62M  … 10.2M           0 ( 0%)        0%

Benchmark 2 (31 runs): /tmp/wild/ripgrep/6/run-with mold
  measurement          mean ± σ            min … max           outliers         delta
  wall_time           165ms ± 27.2ms     149ms …  280ms          2 ( 6%)        ⚡- 86.0% ±  9.9%
  peak_rss           7.84MB ± 96.3KB    7.60MB … 8.00MB         11 (35%)        ⚡- 97.3% ±  0.0%
  cpu_cycles         2.01G  ± 38.6M     1.97G  … 2.16G           2 ( 6%)        ⚡- 19.9% ±  4.8%
  instructions       1.99G  ± 3.12M     1.98G  … 1.99G           3 (10%)        ⚡- 49.3% ±  0.1%
  cache_references   44.8M  ±  250K     44.4M  … 45.6M           1 ( 3%)        ⚡- 54.6% ±  0.9%
  cache_misses       21.6M  ±  461K     21.3M  … 23.6M           3 (10%)        ⚡- 48.4% ±  2.3%
  branch_misses      7.17M  ± 37.7K     7.07M  … 7.25M           1 ( 3%)        ⚡- 26.6% ±  0.8%

Benchmark 3 (56 runs): /tmp/wild/ripgrep/6/run-with wild
  measurement          mean ± σ            min … max           outliers         delta
  wall_time          89.1ms ± 3.14ms    83.0ms … 96.6ms          0 ( 0%)        ⚡- 92.4% ±  7.0%
  peak_rss           3.82MB ± 50.7KB    3.80MB … 3.93MB         10 (18%)        ⚡- 98.7% ±  0.0%
  cpu_cycles         1.26G  ± 15.1M     1.21G  … 1.31G           7 (13%)        ⚡- 49.6% ±  3.4%
  instructions       1.21G  ±  529K     1.21G  … 1.22G           5 ( 9%)        ⚡- 69.1% ±  0.0%
  cache_references   33.9M  ±  467K     32.9M  … 34.9M           0 ( 0%)        ⚡- 65.7% ±  0.8%
  cache_misses       14.4M  ±  187K     14.1M  … 14.9M           0 ( 0%)        ⚡- 65.6% ±  1.5%
  branch_misses      3.49M  ± 7.86K     3.47M  … 3.51M           0 ( 0%)        ⚡- 64.2% ±  0.6%
```

NOTE: Both `mold` and `wild` fork a child process and perform linking in it. Thus, the values for
`peak_rss`, `User` and `System` are for the parent process only, and hence are not representative of
real use by the linker. To avoid this problem, pass `--no-fork` to mold and wild.

NOTE: `poop` uses the first command as the reference the others are compared against, so if focusing
on wild, you might want to re-order the commands and invoke `poop` thus:

```text
poop '/tmp/wild/ripgrep/6/run-with wild' '/tmp/wild/ripgrep/6/run-with mold' '/tmp/wild/ripgrep/6/run-with ld'
```

### Comparisons

Using this method, you can benchmark:

* between Wild and one or more other linkers
* between different options passed to Wild - You can pass arbitrary additional arguments to run-with.
  The first argument needs to be the name of the linker to use. All additional arguments are passed through to the
  linker as-is

### Caching

The use of the linux file system cache affects linker performance, as there is a lot of reasonably
large files read and written. In a normal build, the object files being linked would be written previously by the
compiler and may well be in the file cache. With this benchmarking method we skip the previous build steps and the
linker incurs the penalty of reading those files into cache the first time they are read.

To reduce the effect this has on benchmarked time we run hyperfine with the `--warmup 2` option, and the results
of the first two runs are not used in the calculations.

### Disk write bottlenecks

When benchmarking, if the output file is being written to persistent storage (hard disk or SSD), the
writes can build up and cause the linkers to block. Worse, writes from a previous linker invocation
might contribute to this backlog. Whether this happens depends on how much RAM you have free and
also your kernel settings. For example, if you run `cat /proc/sys/vm/dirty_ratio` that will show the
percentage of reclaimable memory that is allowed to be dirty (needing writing) before further writes
will block. If that shows zero, then `cat /proc/sys/vm/dirty_bytes` will show the same, but as an
absolute number of bytes. On some systems, the absolute dirty byte limit might be set as low as
256MiB, meaning that if we're writing a large output file, we can easily hit this limit. You could
increase this limit, or switch to using `dirty_ratio` of say 20% instead, but it might be better to
just take the filesystem out of the equation and write the output to a tmpfs instead. See next
section.

### Tmpfs

As discussed in the last section, writing to a physical disk can cause inconsistent benchmark
results. It can also contribute to wearing out your SSD. For these reasons, it's recommended to
benchmark with the output file on tmpfs.

If you don't already have a suitable tmpfs to use, you can create one something like the following:

```sh
sudo mkdir /benchmark
sudo mount -t tmpfs none /benchmark
```

Then when running the benchmark, set the output file to be on this filesystem. e.g.:

```sh
OUT=/benchmark/out hyperfine --warmup 2 '/tmp/wild/ripgrep/6/run-with ld' '/tmp/wild/ripgrep/6/run-with mold' '/tmp/wild/ripgrep/6/run-with wild'
```

### Watch out for thermal throttling

If your CPUs get hot while running the benchmark, this can cause inconsistent results. You can check
for throttle events by looking for increases in
`/sys/devices/system/cpu/cpu*/thermal_throttle/package_throttle_count` and
`/sys/devices/system/cpu/cpu*/thermal_throttle/core_throttle_count` between when you start the
benchmark and when you finish. Ideally, these should be unchanged.

One thing that can help is if you have a way to turn your fans to maximum before you start the
benchmark run.

Another possibility is to give the CPUs a chance to cool down between each run, e.g. by sleeping.
With `hyperfine`, you can do this by adding an argument like `--prepare "sleep 2"`. You might need
to experiment with the duration of the sleep.

## What to benchmark

### rustc

When building rustc, most of the rustc code goes into a shared object called rustc-driver. This
shared object is about 230 MiB without debug info and 462 MiB with debug info. While not as large as
some binaries, this is still a pretty reasonable size, making it good for benchmarking. It's also an
interesting benchmark because it's a shared object rather than an executable.

Before building rustc, edit or create `bootstrap.toml` in your `rust` directory to contain:

```toml
[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-Clink-arg=--ld-path=wild"]
```

Now rustc will use wild as the linker on every build. You must have wild in your PATH.
In the following command, replace `$WILD_REPO_PATH` with the path to the directory containing the wild repo. You'll
need to have already built wild with `cargo build --release`.

To build rustc just cd into the rust repo root and run:

```sh
PATH="$WILD_REPO_PATH/target/release:$PATH" WILD_SAVE_BASE=/tmp/rustc-link ./x build rustc
```

For more information about building rustc see [building instructions on the rustc-dev-guide](https://rustc-dev-guide.rust-lang.org/building/how-to-build-and-run.html).
You should now have a few subdirectories under `/tmp/rustc-link`. You can identify which one is
`rustc_driver` by looking at the last line of the `run-with` script in each directory.

If the directory `/tmp/rustc-link` didn't get created, then most likely wild wasn't used to
link.

### Other tools

* [poop](https://github.com/andrewrk/poop) - gives a lot of measurements other than just time. Note
  that the `peak_rss` measurement won't be accurate for wild and mold unless you include the
  `--no-fork` argument to the linker.

## Profiling

### --time

To figure out where wild is spending time, the first option is to run with `--time`. It's
recommended to combine this with `--no-fork`. For example:

```
~/tmp/rustc-link/0/run-with target/release/wild --strip-debug --time --no-fork
┌───    3.84 Open input files
├───    7.45 Split archives
├───    9.59 Parse input files
│ ┌───    2.91 Parse version script
│ ├───   16.67 Read symbols
│ ├───   15.21 Populate symbol map
├─┴─   37.68 Build symbol DB
│ ┌───   29.02 Resolve symbols
│ ├───   33.59 Resolve sections
│ ├───    2.20 Assign section IDs
│ ├───   15.39 Merge strings
│ ├───    0.04 Canonicalise undefined symbols
│ ├───    4.63 Resolve alternative symbol definitions
├─┴─   84.97 Symbol resolution
│ ┌───   76.63 Find required sections
│ ├───    0.16 Merge dynamic symbol definitions
│ ├───   18.74 Finalise per-object sizes
│ ├───    0.12 Apply non-addressable indexes
│ ├───    0.06 Compute total section sizes
│ ├───    0.01 Compute segment layouts
│ ├───    0.00 Compute per-alignment offsets
│ ├───    0.14 Compute per-group start offsets
│ ├───    0.00 Compute merged string section start addresses
│ ├───   18.10 Assign symbol addresses
│ ├───    0.30 Update dynamic symbol resolutions
├─┴─  114.85 Layout
│ ┌───    0.00 Wait for output file creation
│ │ ┌───    0.63 Split output buffers by group
│ ├─┴─  157.42 Write data to file
│ ├───   15.05 Sort .eh_frame_hdr
├─┴─  172.71 Write output file
│ ┌───   14.45 Unmap output file
│ ├───    7.27 Drop layout
│ ├───    0.01 Drop symbol DB
│ ├───   23.35 Drop input data
├─┴─   45.15 Shutdown
└─  481.09 Link
```

If a benchmark has shown a significant increase in say CPU cycles or instructions, then it can be
useful to check which phase or phases that increase has occurred in. You can get per-phase cycle and
instruction counts by running with `--time=cycles,instructions`. To see the full list of counters,
search `args.rs` for "branch-misses".

### Perfetto

The `--time` flag only shows the course stages of the linker. To see what each thread is doing
during each stage, we can capture a perfetto trace and view the results in the perfetto UI.

Start by building with the `perfetto` feature enabled:

```sh
cargo build --release --features perfetto
```

Run the linker with `WILD_PERFETTO_OUT` set to some file. e.g.:

```sh
WILD_PERFETTO_OUT=$HOME/tmp/tmp.pftrace ./run-with wild
```

Open the [perfetto UI](https://ui.perfetto.dev/). Click "Open trace file" and select `tmp.pftrace`.
Use the keys w, a, s, d to navigate (scroll and zoom).

### Samply

To look for hot functions and to check how the work distribution looks between threads, you can use
[samply](https://github.com/mstange/samply).

For this to be useful, you likely want optimisations and debug info. We have an `opt-debug` profile
set up for this purpose.

```sh
cargo build --profile opt-debug
```

```sh
~/tmp/rustc-link/0/run-with samply record target/opt-debug/wild --strip-debug
```

The result will look something [like this](https://share.firefox.dev/4eORM7r). This is using the
Firefox profiler, so you'll need to open that link in Firefox.

One thing you'll likely notice when looking at the flamegraph is that there's lots of rayon stuff
and that makes it hard to see what's going on. The issue is that rayon uses recursion and the exact
sequence of calls it goes through before it gets to our code varies. The trick to seeing through
this is to collapse that recursion. For example, find
`rayon::iter::plumbing::bridge_producer_consumer::helper`, right click and select `Collapse
recursion` (or 'r'). If there's any extra rayon stack frames that you'd like to ignore, you can
select them and press 'm' to merge them.

### Heap profiling with dhat

Build with profiling enabled:

```sh
cargo build --profile opt-debug --features dhat
```

Then run the linker on some input. e.g:

```sh
~/tmp/rustc-link/0/run-with target/opt-debug/wild --no-fork
```

This should print some stats on exit. e.g.:

```
dhat: Total:     250,699,127 bytes in 130,224 blocks
dhat: At t-gmax: 111,265,627 bytes in 14,117 blocks
dhat: At t-end:  96,320 bytes in 109 blocks
dhat: The data has been saved to dhat-heap.json, and is viewable with dhat/dh_view.html
```

You can then upload `dhat-heap.json` to the [online dhat
viewer](https://nnethercote.github.io/dh_view/dh_view.html).

For more details, see the [dhat docs](https://docs.rs/dhat/latest/dhat/).

### Generating report-style benchmarks

Benchmarks such as [benchmarks/ryzen-9955hx.md](benchmarks/ryzen-9955hx.md) are generated using the
tool in `benchmarks/runner`. You'll need a directory containing one or more "save-dirs" where the
names of the directories are the names of the benchmarks.

```sh
cargo run --bin benchmark-runner -- \
    bench --config benchmarks/ryzen-9955hx.toml --save ~/save linker1 linker2 linker3
cargo run --bin benchmark-runner -- report
```
