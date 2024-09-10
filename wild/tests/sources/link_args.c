//#Config:strip-all
//#Object:exit.c
//#LinkArgs:--strip-all
//#EnableLinker:lld

//#Config:single-threaded
//#Object:exit.c
//#WildExtraLinkArgs:--threads=1

// TODO: Figure out why this fails in CI and fix it.
// #Config:dev_null
// #Object:exit.c
// #LinkArgs:-o /dev/null

#include "exit.h"

void _start(void) {
    exit_syscall(42);
}
