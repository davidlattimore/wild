// Extracted from https://github.com/rust-lang/rust/issues/146780
//#Config:pie-over-shared
//#LinkArgs:-shared -z now -pie
//#DiffIgnore:.dynamic.DT_RELA*
// We're linking different .so files, so this is expected.
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:section.got
//#Shared:runtime.c
//#Mode:dynamic

//#Config:no-pie-over-shared
//#LinkArgs:-shared -z now -no-pie
//#Object:runtime.c

#include "runtime.h"

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
