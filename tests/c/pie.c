//#CompArgs:pie:-static -pie
//#LinkArgs:pie:-static -pie --no-dynamic-linker

#include "exit.h"

#include <stdint.h>

struct Dyn {
    uint64_t tag;
    uint64_t value;
};

extern struct Dyn _DYNAMIC[];

void _start(void) {
    struct Dyn* d = _DYNAMIC;
    if (!d) {
        exit_syscall(100);
    }
    int got_flags1 = 0;
    while (d->tag != 0) {
        if (d->tag == 0x000000006ffffffb) {
            got_flags1 = 1;
        }
        d++;
    }

    if (!got_flags1) {
        exit_syscall(101);
    }

    exit_syscall(42);
}
