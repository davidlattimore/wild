#include "exit.h"

void _start(void) {
    exit_syscall(42);
}

//#LinkArgs:default:
//#LinkArgs:strip-all:--strip-all
