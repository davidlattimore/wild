//#Config:strip-all
//#Object:exit.c
//#LinkArgs:--strip-all
//#EnableLinker:lld

#include "exit.h"

void _start(void) {
    exit_syscall(42);
}
