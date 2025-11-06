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

// Only loaded libs should affect output kind
//#Config:unloaded-dso
//#LinkArgs:-z now -as-needed
//#Object:runtime.c
//#Shared:empty.c
//#Mode:unspecified
//#RunEnabled:false

#include "runtime.h"

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
