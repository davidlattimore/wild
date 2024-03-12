// Defines identical string literals in two different C files and checks that they end up pointing
// to the same memory.

#include "exit.h"

extern const char s1h[];
extern const char s2h[];
extern const char s3h[];
extern const char s4h[];
extern const char s1w[];
extern const char s2w[];
extern const char a1[];

const char* get_loc1(void);
const char* get_s1w(void);
const char* get_s2w(void);

void _start(void) {
    if (s1h != s2h) {
        exit_syscall(101);
    }
    if (s1h[0] != 'H') {
        exit_syscall(103);
    }
    if (s1w != s2w) {
        exit_syscall(102);
    }
    if (s1w[0] != 'W') {
        exit_syscall(103);
    }
    if (get_loc1()[0] != 'L') {
        exit_syscall(104);
    }
    if (a1[0] != 'A') {
        exit_syscall(105);
    }
    if (get_s1w() != get_s2w()) {
        exit_syscall(106);
    }
    if (get_s1w() != s1w) {
        exit_syscall(107);
    }
    if (s3h != s4h) {
        // Identical strings in the same custom section didn't get merged.
        exit_syscall(108);
    }
    if (s3h == s1h) {
        // Identical strings in different sections got merged when they shouldn't have been.
        exit_syscall(109);
    }
    if (s3h[0] != 'H') {
        exit_syscall(110);
    }
    exit_syscall(42);
}
