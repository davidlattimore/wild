//#Object:runtime.c
//#Object:wrap-1.c
//#Object:wrap-2.c
//#LinkArgs:--wrap=foo --wrap=bar --wrap=baz
// linker-diff doesn't currently understand wrapped symbols.
//#DiffIgnore:rel.R_X86_64_PC32.R_X86_64_PC32
//#DiffIgnore:rel.R_AARCH64_CALL26.R_AARCH64_CALL26

#include "runtime.h"

// Defined weakly in wrap-1, but that gets overridden by the strong definition in wrap-2.
int foo(void);
int __real_foo(void);

// Defined strongly only in wrap-1
int bar(void);
int __real_bar(void);

// Note, we don't define `baz` despite passing `--wrap=baz`. We shouldn't error, since we also don't
// have any references to `baz`.

int __wrap_foo(void) {
	return __real_foo() + 2;
}

int __wrap_bar(void) {
	return __real_bar() + 5;
}

void _start(void) {
    runtime_init();

    if (foo() != 42) {
        exit_syscall(100);
    }

    if (bar() != 25) {
        exit_syscall(101);
    }

    exit_syscall(42);
}
