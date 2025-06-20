//#Object:preinit-array.s
//#Shared:runtime.c
// We're linking different .so files, so this is expected.
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:segment.LOAD.RW.alignment
//#DiffIgnore:.dynamic.DT_PREINIT_ARRAY
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT
//#Arch: x86_64
//#RequiresGlibc:true
//#Mode:dynamic

#include "runtime.h"

int exit_code;

void preinit() {
    exit_code = 42;
}

void _start(void) {
    runtime_init();
    exit_syscall(exit_code);
}
