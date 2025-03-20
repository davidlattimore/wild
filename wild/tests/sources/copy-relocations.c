//#Object:exit.c
//#EnableLinker:lld
//#Static:false
//#CompSoArgs:-fPIC
//#LinkArgs:-z now
//#Shared:copy-relocations-2.c
// We're linking different .so files, so this is expected.
//#DiffIgnore:.dynamic.DT_NEEDED

#include "exit.h"

// These two symbols are at the same address in the shared object, so references to both should
// point to the same copy relocation and that location should be what `get_foo` returns.
extern int foo;
extern int bar;
int get_foo(void);

// This time we only reference the non-weak symbol.
extern int foo2;
int get_foo2(void);

// Lastly, we reference the weak symbol and not the strong one.
extern int bar3;
int get_foo3(void);

void _start(void) {
    foo = 10;
    if (get_foo() != 10) {
        exit_syscall(20);
    }
    bar = 11;
    if (get_foo() != 11) {
        exit_syscall(21);
    }

    foo2 = 12;
    if (get_foo2() != 12) {
        exit_syscall(22);
    }

    bar3 = 13;
    if (get_foo3() != 13) {
        exit_syscall(23);
    }

    exit_syscall(42);
}
