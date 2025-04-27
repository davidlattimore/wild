//#Object:init.c
//#Object:runtime.c
//#CompArgs:default:
//#CompArgs:-static -pie

#include "runtime.h"
#include "init.h"

static int value = 0;

void __attribute__ ((constructor)) premain() {
    value = 42;
}

void _start(void) {
    runtime_init();
    call_init_functions();
    exit_syscall(value);
}
