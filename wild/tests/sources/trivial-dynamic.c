//#Config:default
//#Object:runtime.c
//#EnableLinker:lld
//#Mode:dynamic
//#LinkArgs:-z now
//#Shared:trivial-dynamic-2.c
//#EnableLinker:lld
// We're linking different .so files, so this is expected.
//#DiffIgnore:.dynamic.DT_NEEDED
// We put a GLOB_DAT in .rela.dyn, other linkers use a JUMP_SLOT in .rela.plt.
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT
// On aarch64, GNU ld seems to emit a GOT in the shared object even though it isn't needed.
//#DiffIgnore:section.got

//#Config:origin:default
//#LinkArgs:-z now -z origin

//#Config:nodelete:default
//#LinkArgs:-z now -z nodelete

//#Config:symbolic:default
//#LinkArgs:-z now -Bsymbolic
// TODO: Set these
//#DiffIgnore:.dynamic.DT_FLAGS.SYMBOLIC
//#DiffIgnore:.dynamic.DT_SYMBOLIC

#include "runtime.h"

int foo(void);

typedef int(*get_int_fn_t)(void);

get_int_fn_t foo_ptr = foo;

void _start(void) {
    runtime_init();

    if (foo() != 10) {
        exit_syscall(20);
    }

    if (foo_ptr() != 10) {
        exit_syscall(21);
    }

    exit_syscall(42);
}
