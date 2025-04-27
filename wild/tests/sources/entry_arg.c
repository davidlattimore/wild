//#Object:runtime.c
//#LinkArgs:--entry=custom_entry

#include "runtime.h"

void custom_entry(void) {
    runtime_init();
    exit_syscall(42);
}
