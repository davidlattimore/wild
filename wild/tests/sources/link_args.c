//#Config:strip-all
//#Object:runtime.c
//#LinkArgs:--strip-all
//#EnableLinker:lld
//#DiffIgnore:file-header.entry

//#Config:single-threaded
//#Object:runtime.c
//#WildExtraLinkArgs:--threads=1

//#Config:dev_null
//#Object:runtime.c
//#LinkArgs:-o /dev/null
//#DiffEnabled:false
//#RunEnabled:false

#include "runtime.h"

void _start(void) {
    runtime_init();
    exit_syscall(42);
}
