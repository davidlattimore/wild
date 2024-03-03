#include "exit.h"

void _start(void) {
    exit_syscall(42);
}

//#ExpectSym: _start
//#ExpectSym: exit_syscall
