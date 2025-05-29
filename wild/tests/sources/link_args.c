//#Config:strip-all
//#Object:runtime.c
//#LinkArgs:--strip-all
//#EnableLinker:lld
//#DiffIgnore:file-header.entry
// TODO: #795
//#Arch: x86_64,aarch64

//#Config:single-threaded
//#Object:runtime.c
//#WildExtraLinkArgs:--threads=1

//#Config:dev_null
//#Object:runtime.c
//#LinkArgs:-o /dev/null
//#DiffEnabled:false
//#RunEnabled:false

//#Config:gc-sections
//#CompArgs:-g -ffunction-sections
//#LinkArgs:--gc-sections
//#Object:runtime.c
//#NoSym:this_function_is_not_used

#include "runtime.h"

void _start(void) {
    runtime_init();
    exit_syscall(42);
}

void this_function_is_not_used(void) {}
