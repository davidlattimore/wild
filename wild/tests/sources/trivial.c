//#Object:exit.c
//#ExpectSym: _start .text
//#ExpectSym: exit_syscall .text
//#EnableLinker:lld
//#LinkArgs: -v

#include "exit.h"

void _start(void) {
    exit_syscall(42);
}
