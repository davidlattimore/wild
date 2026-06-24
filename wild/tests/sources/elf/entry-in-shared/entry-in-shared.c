// https://github.com/wild-linker/wild/issues/1137
//#Config:entry-in-shared
//#SkipArch: ppc64le
//#LinkArgs:-shared -z now
//#RunEnabled:false
//#Object:runtime.c
//#DiffIgnore:.dynamic.DT_RELA*
//#Mode:dynamic

#include "../common/runtime.h"

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
