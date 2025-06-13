//#AbstractConfig:default
//#Object:runtime.c
//#Static:false
//#Shared:shlib-undefined-2.c

//#Config:allow:default
//#LinkArgs:--allow-shlib-undefined -z now
//#RunEnabled:false
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT
//#DiffIgnore:.dynamic.DT_NEEDED

//#Config:disallow:default
//#LinkArgs:--no-allow-shlib-undefined
//#ExpectError:def2

#include "runtime.h"

int def1(void) {
    return 100;
}

int call_def1(void);

void _start(void) {
    runtime_init();
    exit_syscall(call_def1());
}
