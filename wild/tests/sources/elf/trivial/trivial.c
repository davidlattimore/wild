//#Object:runtime.c
//#ExpectSym:_start section=".text"
//#ExpectSym:exit_syscall section=".text"
//#EnableLinker:lld
//#TestUpdateInPlace:true

#include "runtime.h"

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
