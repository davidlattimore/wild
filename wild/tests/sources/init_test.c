//#Object:init.c
//#Object:exit.c
//#CompArgs:default:
//#CompArgs:-static -pie

#include "exit.h"
#include "init.h"

static int value = 0;

void __attribute__ ((constructor)) premain() {
    value = 42;
}

void _start(void) {
    call_init_functions();
    exit_syscall(value);
}
