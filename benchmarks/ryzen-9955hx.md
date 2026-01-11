# Benchmarks

This page contains benchmarks of linking various programs. The benchmarks are just running the
linker, not the compiler. All benchmarks are run on an AMD Ryzen 9 9955HX 16-Core (32 thread)
processor with 92GiB of RAM. The output file is always on tmpfs.

For benchmarks run on David's 2020 era laptop which were used in benchmark reports prior to 2026,
see [lemp9.md](lemp9.md).

The benchmarks include several other linkers for Linux as well as several recent versions of Wild.
This allows us to both compare between linkers and to see how Wild's performance is changing over
time.

We only include GNU ld (BFD) in a few of the benchmarks since it's generally a lot slower than the
other linkers and including it messes up the scaling on the charts. It does do OK on memory
consumption though.

The little white ticks on each bar are 99% confidence intervals and show how accurate we think our
mean value is. i.e. if we reran the benchmark 100 times, we'd expect that 99 times we'd get a mean
within that the range of the white tick.

## Execution time

### chrome - time

We start with linking the Chrome web browser (technically Chromium). This is a very large codebase
and a pretty large binary.

![Benchmark of linking chrome](images/ryzen-9955hx/chrome-time.svg)

### chrome-crel - time

CREL relocations are a new format for relocations that is significantly more compact. Wild has
supported these for a couple of releases, however we hadn't benchmarked non-trivial programs with
CREL relocations until just prior to the 0.8.0 release. It turned out that we had a bug that caused
memory usage to blow up, making it impractical to link non-trivial programs. This is now fixed, so
we benchmark CREL relocations from 0.8.0. Chrome uses CREL relocations by default.

![Benchmark of linking chrome-crel](images/ryzen-9955hx/chrome-crel-time.svg)

### mold-crel - time

For a smaller CREL benchmark, we link Mold, with the compiler configured to emit CREL relocations
(not the default configuration).

![Benchmark of linking mold-crel](images/ryzen-9955hx/mold-crel-time.svg)

### clang-debug - time

Clang with debug info has massive quantities of debug strings that need to be deduplicated. So link
time here is dominated by how quickly we can deduplicate strings.

![Benchmark of linking clang-debug](images/ryzen-9955hx/clang-debug-time.svg)

### clang-debug-strip - time

This benchmark is the same as the previous one, but with the extra flag `--strip-debug`. It shows to
what extent linkers are able to take advantage of the fact that they don't need to emit the debug
info that's in the input files.

![Time to link clang-debug-strip](images/ryzen-9955hx/clang-debug-strip-time.svg)

### clang-release - time
![Benchmark of linking clang-release](images/ryzen-9955hx/clang-release-time.svg)

### rust-analyzer - time
![Benchmark of linking rust-analyzer](images/ryzen-9955hx/rust-analyzer-time.svg)

### rust-analyzer-riscv - time
![Benchmark of linking rust-analyzer-riscv](images/ryzen-9955hx/rust-analyzer-riscv-time.svg)

### zed - time
![Benchmark of linking zed](images/ryzen-9955hx/zed-time.svg)

### zed-release - time
![Benchmark of linking zed-release](images/ryzen-9955hx/zed-release-time.svg)

### bevy-dylib - time
![Benchmark of linking bevy-dylib](images/ryzen-9955hx/bevy-dylib-time.svg)

### librustc-driver - time

Rustc is quite large. Most of the code however goes into librustc-driver. Rustc itself it pretty
quick to link, so we only benchmark linking of librustc-driver.

![Benchmark of linking librustc-driver](images/ryzen-9955hx/librustc-driver-time.svg)

### ripgrep - time

Ripgrep is a popular grep alternative. It's got a pretty lean dependency tree, so is fairly fast to
link.

![Benchmark of linking ripgrep](images/ryzen-9955hx/ripgrep-time.svg)

### wild - time

Wild linking itself.

![Benchmark of linking wild](images/ryzen-9955hx/wild-time.svg)

### wild-riscv - time

Wild linking a risc-v version of itself. We're still doing the linking on x86_64, but the binary
being produced is for risc-v.

![Benchmark of linking wild-riscv](images/ryzen-9955hx/wild-riscv-time.svg)

### rust-hello-world - time

Now a couple of trivial, hello-world programs. One written in Rust and one written in C.

![Benchmark of linking rust-hello-world](images/ryzen-9955hx/rust-hello-world-time.svg)

### c-hello-world - time
![Benchmark of linking c-hello-world](images/ryzen-9955hx/c-hello-world-time.svg)

## Memory consumption

We care not just about execution time, but also memory consumption. Here are the same benchmarks as
above repeated, but this time measuring the peak memory consumption of the linkers.

### chrome - memory
![Memory consumption while linking chrome](images/ryzen-9955hx/chrome-memory.svg)

### chrome-crel - memory
![Memory consumption while linking chrome-crel](images/ryzen-9955hx/chrome-crel-memory.svg)

### mold-crel - memory
![Memory consumption while linking mold-crel](images/ryzen-9955hx/mold-crel-memory.svg)

### clang-debug - memory
![Memory consumption while linking clang-debug](images/ryzen-9955hx/clang-debug-memory.svg)

### clang-debug-strip - memory
![Memory consumption while linking clang-debug-strip](images/ryzen-9955hx/clang-debug-strip-memory.svg)

### clang-release - memory
![Memory consumption while linking clang-release](images/ryzen-9955hx/clang-release-memory.svg)

### rust-analyzer - memory
![Memory consumption while linking rust-analyzer](images/ryzen-9955hx/rust-analyzer-memory.svg)

### rust-analyzer-riscv - memory
![Memory consumption while linking rust-analyzer-riscv](images/ryzen-9955hx/rust-analyzer-riscv-memory.svg)

### zed - memory
![Memory consumption while linking zed](images/ryzen-9955hx/zed-memory.svg)

### zed-release - memory
![Memory consumption while linking zed-release](images/ryzen-9955hx/zed-release-memory.svg)

### bevy-dylib - memory
![Memory consumption while linking bevy-dylib](images/ryzen-9955hx/bevy-dylib-memory.svg)

### librustc-driver - memory
![Memory consumption while linking librustc-driver](images/ryzen-9955hx/librustc-driver-memory.svg)

### ripgrep - memory
![Memory consumption while linking ripgrep](images/ryzen-9955hx/ripgrep-memory.svg)

### wild - memory
![Memory consumption while linking wild](images/ryzen-9955hx/wild-memory.svg)

### wild-riscv - memory
![Memory consumption while linking wild-riscv](images/ryzen-9955hx/wild-riscv-memory.svg)

### rust-hello-world - memory
![Memory consumption while linking rust-hello-world](images/ryzen-9955hx/rust-hello-world-memory.svg)

### c-hello-world - memory
![Memory consumption while linking c-hello-world](images/ryzen-9955hx/c-hello-world-memory.svg)

