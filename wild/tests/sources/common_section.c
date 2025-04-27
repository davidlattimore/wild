//#CompArgs:-fcommon
//#Object:common_section0.c
//#Object:common_section1.c
//#Object:runtime.c
//#EnableLinker:lld

#include "runtime.h"

int a;
extern int data[];
extern int q[];
extern int z[];

void _start(void) {
    runtime_init();

    a = 30;
    q[0] = 20;
    z[0] = 40;
    // We have two declarations of `data`. One has size 10, the other 1000. The linker should choose
    // the one with the larger size.
    for (int i = 0; i < 1000; i++) {
        data[i] = 6;
    }
    // Try to detect if we've overflowed the space allocated to data. It's luck whether the linker
    // decides to put any of our canary variables after `data`, but if we have enough of them, then
    // there's a reasonable chance.
    if (a != 30 || q[0] != 20 || z[0] != 40) {
        exit_syscall(101);
    }
    data[100] = 10;
    exit_syscall(42);
}

//#ExpectSym: a .bss
//#ExpectSym: data .bss
//#ExpectSym: q .bss
//#ExpectSym: z .bss
