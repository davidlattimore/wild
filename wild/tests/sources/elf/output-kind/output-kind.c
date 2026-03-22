// The logic of  choosing output kind in LD is so convoluted we sometimes stick
// to LLD because of either the code complexity (and performance) or providing a
// better user experience.
// This series of tests makes sure we keep the alignment.

//#AbstractConfig:default
//#EnableLinker:lld
//#DiffIgnore:section.relro_padding

// `-no-pie` should override `-shared`, and `-pie --dynamic-linker ..` should
// result in dynamic PIE. LLD rejects this with an error.
//#Config:pie-over-shared
//#LinkArgs:-shared -z now -pie
//#Object:runtime.c
//#Mode:dynamic
//#DiffIgnore:section.got

// `-no-pie` should override `-shared`. LLD rejects this with an error.
//#Config:no-pie-over-shared
//#LinkArgs:-shared -z now -no-pie
//#Object:runtime.c

// Loaded DSO turns static non-relocatable executable into dynamic one if
// dynamic linker is set.
//#Config:loaded-dso:default
//#LinkArgs:-z now
//#Object:runtime.c
//#Shared:empty.c
//#Mode:dynamic
//#DiffIgnore:.dynamic.DT_NEEDED

// With GNU ld non-loaded DSO has no effect on output kind, but LLD's approach
// simplifies code a lot.
//#Config:non-loaded-dso:default
//#LinkArgs:-z now --as-needed
//#Object:runtime.c
//#Shared:empty.c
//#Mode:unspecified
//#SkipLinker:ld

// Setting dynamic linker doesn't change output kind for non-PIE.
// LLD sets requested interpreter, but GNU ld doesn't. We follow GNU ld this
// time.
//#Config:dynamic-linker
//#LinkArgs:-z now --dynamic-linker=/lib64/bad.so
//#Object:runtime.c
//#Mode:unspecified

// GNU ld creates static PIE only when both `--no-dynamic-linker` and `-pie` are
// present. There are three approaches we can take for this case: emit PIE with
// incorrect interpreter like GNU ld does (at least on x86_64 Linux), emit
// static PIE like LLD, or emit PIE with correct implicit interpreter unlike
// other linkers. This time we follow what LLD does.
//#Config:pie-default-dynamic-linker:default
//#LinkArgs:-z now -pie
//#Object:runtime.c
//#EnableLinker:lld
//#SkipLinker:ld
//#Mode:unspecified

#include "runtime.h"

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
