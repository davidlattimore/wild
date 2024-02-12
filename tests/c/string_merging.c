// Defines identical string literals in two different C files and checks that they end up pointing
// to the same memory.

#include "exit.h"

extern const char s1h[];
extern const char s2h[];
extern const char s1w[];
extern const char s2w[];
extern const char s1nz[];
extern const char s2nz[];

const char* get_loc1(void);

void _start(void) {
    if (s1h != s2h) {
        exit_syscall(101);
    }
    if (s1w != s2w) {
        exit_syscall(102);
    }
    if (s1nz != s2nz) {
        exit_syscall(103);
    }
    if (get_loc1()[0] != 'L') {
        exit_syscall(104);
    }
    exit_syscall(42);
}
