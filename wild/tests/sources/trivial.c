//#Object:runtime.c
//#ExpectSym: _start .text
//#ExpectSym: exit_syscall .text
//#DiffIgnore: section.got
//#EnableLinker:lld

#include "runtime.h"

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
