//#Config:strip-all
//#Object:exit.c
//#LinkArgs:--strip-all

#include "exit.h"

void _start(void) {
    exit_syscall(42);
}
