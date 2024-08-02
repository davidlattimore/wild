// This test checks that we correctly handle the .init and .fini sections. These section is a bit
// different to other sections in that glibc defines the start of the _init function in one file
// (crti.o) and then any other objects that define code for the .init section need to appear after
// this with no padding in between. The end of the function is then from crtn.o which has the return
// instruction. Of these .init sections, the only one with alignment >1 is the start of the
// function. This is tricky for us since normally we pad all sections to a multiple of their
// alignment. We can't do that here because then we'd end up with zero bytes in the middle of our
// _init function.

//#Object:old_init0.s
//#Object:old_init1.s
//#Object:exit.c
//#LinkArgs:-z noexecstack
//#EnableLinker:lld

#include "exit.h"

int _init();
int _fini();

void _start(void) {
    if (_init() != 7) {
        exit_syscall(1);
    }
    if (_fini() != 9) {
        exit_syscall(2);
    }
    exit_syscall(42);
}
