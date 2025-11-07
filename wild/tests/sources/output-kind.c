// This is a series of tests to make sure we follow LD's convoluted logic for
// choosing output kind.

// `(-no)-pie` should override `-shared`
//#Config:pie-over-shared
//#LinkArgs:-shared -z now -pie
//#Object:runtime.c
//#Mode:dynamic
//
//#Config:no-pie-over-shared
//#LinkArgs:-shared -z now -no-pie
//#Object:runtime.c

// Loaded DSO turns static non-relocatable executable into dynamic one if
// dynamic linker is set.
//#Config:loaded-dso
//#LinkArgs:-z now
//#Object:runtime.c
//#Shared:empty.c
//#Mode:dynamic
//#DiffIgnore:.dynamic.DT_NEEDED

// Not loaded DSO has no effect on output kind.
//#Config:not-loaded-dso
//#LinkArgs:-z now --as-needed
//#Object:runtime.c
//#Shared:empty.c
//#Mode:unspecified

// Setting dynamic linker doesn't change output kind on its own.
//#Config:dynamic-linker
//#LinkArgs:-z now --dynamic-linker=/lib64/bad.so
//#Object:runtime.c
//#Mode:unspecified

// Unlike other linkers, LD creates static PIE only when both
// `--no-dynamic-linker` and `-pie` are present.
// There are three approaches for
// this case: emit PIE with incorrect interpreter like LD (at least on x86_64
// Linux), emit static PIE like LLD, or emit PIE with correct implicit
// interpreter unlike other linkers. This time we follow what LLD does.
//#Config:wip
//#LinkArgs:-z now -pie
//#Object:runtime.c
//#EnableLinker:lld
//#SkipLinker:ld
//#Mode:unspecified
//#DiffIgnore:section.relro_padding

#include "runtime.h"

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
