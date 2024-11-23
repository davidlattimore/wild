# Benchmarking Wild

## Benchmarking against other linkers

If you decide to benchmark Wild against other linkers, in order to make it a fair comparison, you
should ensure that the other linkers aren't doing work on something that Wild doesn't support. In
particular:

* Wild defaults to `--gc-sections`, so for a fair comparison, that should be passed to all the
  linkers.
* Wild defaults to `-z now`, so best to pass that to all linkers.

There might be other flags that speed up the other linkers by letting them avoid some work that
they're currently doing. If you know of such flags, please let me know.

## Unknowns and future work

Many unknowns remain and I want to improve the benchmarking of wild over time, to reduce them, or
to quantify them as feature set grows and wild (and other linkers) evolve over time

* Will the results be significantly different between linkers depending on the packages being linked?
* How will Wild perform when linking much larger binaries.
* How will Wild scale when running on systems with many CPU cores?
* Will implementing the missing features require changes to Wild's design slow it down?