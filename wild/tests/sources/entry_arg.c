//#Object:exit.c
//#LinkArgs:--entry=custom_entry

#include "exit.h"

void custom_entry(void) {
    exit_syscall(42);
}
