#include "exit.h"
#include <stddef.h>

static char data1[] = "QQQ";

// Specify an alignment that is larger than the size of the data we're putting in the section.
__attribute__ ((aligned (64)))
static char data2[] = "abcdefghijklmnopqrstuvwxyz";

void _start(void) {
    if (data1[0] != 'Q') {
        exit_syscall(1);
    }
    if ((size_t)data2 & 63 != 0) {
        exit_syscall(2);
    }
    if (data2[0] != 'a' || data2[sizeof(data2) - 2] != 'z') {
        exit_syscall(3);
    }
    exit_syscall(42);
}
