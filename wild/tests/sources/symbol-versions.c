//#Object:exit.c
//#Object:symbol-versions-2.c
//#ExpectSym: _start .text
//#ExpectSym: exit_syscall .text
//#EnableLinker:lld

#include "exit.h"

int foo(void);

void _start(void) {
    if (foo() != 2) {
        exit_syscall(foo());
    }

    exit_syscall(42);
}
