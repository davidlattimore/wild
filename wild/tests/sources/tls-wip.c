//#Config:wip
//#LinkArgs:-z now -no-pie
//#Mode:dynamic
//#Shared:runtime.c
//#DiffIgnore:section.rodata
//#DiffIgnore:.dynamic.*

#include "runtime.h"

__thread int tvar __attribute__((common));

void _start() {
  runtime_init();
  tvar += 41;
  exit_syscall(++tvar);
}
