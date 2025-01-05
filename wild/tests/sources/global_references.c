#include "exit.h"
#include "global_definitions.h"

#include <stddef.h>

// Returns the passed value, but don't let the compiler make any assumptions about the returned
// value.
#if defined(__x86_64__)
int black_box(int input) {
    register int rdi __asm__ ("rdi") = input;
    __asm__ __volatile__ (
        "nop"
        : "+r" (rdi)
    );
    return rdi;
}
#elif defined(__aarch64__)
int black_box(int input) {
    register int w0 __asm__ ("w0") = input;
    __asm__ __volatile__ (
        "nop"
        : "+r" (w0)
    );
    return w0;
}
#endif

void _start() {
    if (global_value != 38) {
        exit_syscall(100);
    }
    if (global_values[3] != 4) {
        exit_syscall(101);
    }
    // Without passing our value through a black box, the compiler gets rid of the if-statement
    // below, treating it as always true, since it figures that an integer obtained from a pointer
    // can never be equal to 25.
    int abs1_value = black_box((size_t)&abs1);
    if (abs1_value != 25) {
        exit_syscall(abs1_value);
    }
    exit_syscall(42);
}
