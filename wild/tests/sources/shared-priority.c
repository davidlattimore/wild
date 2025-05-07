// Tests related to how we handle symbols that are defined in shared objects and also in other
// places like archives.

//#AbstractConfig:default
//#CompArgs:-fPIC
//#Object:runtime.c
//#Static:false
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT
//#DiffIgnore:section.got
// TODO: RISC-V BFD linker keeps the symbol in .dynsym section
//#DiffIgnore:section.rela.dyn
//#DiffIgnore:dynsym.var1.section

//#Config:shared-first-archive-not-loaded:default
//#Shared:shared-priority-1.c
//#Archive:shared-priority-2.c

//#Config:archive-first:default
//#Archive:shared-priority-1.c
//#Shared:shared-priority-2.c

#include "runtime.h"

int foo(void);

extern int var1;

void _start(void) {
    runtime_init();

    if (var1 != 65) {
        exit_syscall(101);
    }
    if (foo() != 10) {
        exit_syscall(100);
    }
    exit_syscall(42);
}
