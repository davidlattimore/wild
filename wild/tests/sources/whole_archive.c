//#Object:exit.c
//#LinkArgs:--whole-archive
//#Archive:whole_archive0.c
//#Cross:false

#include "exit.h"

extern int __start_foo[];
extern int __stop_foo[];

void _start(void) {
    int value = 0;

    for (int *foo = __start_foo; foo < __stop_foo; ++foo) {
        value += *foo;
    }

    exit_syscall(value);
}
