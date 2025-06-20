//#Object:runtime.c
//#LinkArgs:--whole-archive
//#Archive:whole_archive0.c

#include "runtime.h"

extern int __start_foo[];
extern int __stop_foo[];

void _start(void) {
    runtime_init();

    int value = 0;

    for (int *foo = __start_foo; foo < __stop_foo; ++foo) {
        value += *foo;
    }

    exit_syscall(value);
}
