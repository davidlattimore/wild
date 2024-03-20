// Checks that we work correctly when there's a GOT reference to a local. I'm not entirely sure why
// you'd have a GOT reference to a local, but it is something I've observed.

#include "exit.h"

typedef int (*fnptr)(void);

fnptr get_foo1(void);
fnptr get_foo2(void);

void _start(void) {
    if (get_foo1()() != 2) {
        exit_syscall(100);
    }
    if (get_foo2()() != 22) {
        exit_syscall(101);
    }
    exit_syscall(42);
}
