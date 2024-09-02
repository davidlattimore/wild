//#Config:strip-all
//#Object:exit.c
//#LinkArgs:--strip-all
//#EnableLinker:lld

//#Config:single-threaded
//#Object:exit.c
//#WildExtraLinkArgs:--threads=1

#include "exit.h"

void _start(void) {
    exit_syscall(42);
}
