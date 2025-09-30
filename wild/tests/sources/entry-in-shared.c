// https://github.com/davidlattimore/wild/issues/1137
//#Config:entry-in-shared
//#LinkArgs:-shared -z now
//#Object:runtime.c
//#DiffIgnore:.dynamic.DT_RELA*
//#Mode:dynamic

#include "runtime.h"

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
