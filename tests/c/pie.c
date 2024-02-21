//#CompArgs:pie:-static -pie
//#LinkArgs:pie:-static -pie --no-dynamic-linker

#include "exit.h"

extern void* _DYNAMIC;

void _start(void) {
    if (!_DYNAMIC) {
        exit_syscall(100);
    }
    exit_syscall(42);
}
