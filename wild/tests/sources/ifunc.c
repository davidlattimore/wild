//#Object:ifunc1.c
//#Object:ifunc_init.c
//#Object:exit.c

#include "exit.h"
#include "init.h"
#include "ifunc_init.h"

extern int compute_value10(void);
extern int compute_value32(void);

extern int resolve_count;

typedef int (*vptr)(void);

const vptr v10_ptr = compute_value10;

void _start(void) {
    int rv = init_ifuncs();
    if (rv != 0) {
        exit_syscall(rv);
    }
    if (compute_value10() != 10) {
        exit_syscall(1);
    }
    if (compute_value32() != 32) {
        exit_syscall(2);
    }
    if (v10_ptr() != 10) {
        exit_syscall(3);
    }
    if (resolve_count != 2) {
        exit_syscall(4);
    }
    if (v10_ptr == compute_value32) {
        exit_syscall(5);
    }
    if (v10_ptr != compute_value10) {
        exit_syscall(5);
    }
    exit_syscall(42);
}
