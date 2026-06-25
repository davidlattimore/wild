//#Object:runtime.c
//#ExpectSym:_start section=".text"
//#ExpectSym:exit_syscall section=".text"
//#ReferenceLinkers:bfd,lld
//#TestUpdateInPlace:true

#include "../common/runtime.h"

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
