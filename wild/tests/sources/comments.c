//#Object:comments0.c
//#Object:comments1.c
//#Object:exit.c

#include "exit.h"

int v0(void);
int v1(void);

void _start(void) {
    // References functions are here just to make sure we're using a symbol for each of our files,
    // otherwise the .comment section doesn't get used.
    if (v0() != 4) {
        exit_syscall(100);
    }
    if (v1() != 5) {
        exit_syscall(101);
    }
    exit_syscall(42);
}

//#ExpectComment:Foo
//#ExpectComment:Bar
