//#Object:runtime.c
//#ExpectSym: _start .text
//#ExpectSym: exit_syscall .text
//#EnableLinker:lld
//#LinkArgs: -v

#include "runtime.h"

void _start(void) {
    runtime_init();
    exit_syscall(42);
}
