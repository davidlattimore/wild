//#Config:default
//#Object:runtime.c
//#ExpectEntry:_main
//#DiffIgnore:section.__unwind_info

#include "../common/runtime.h"

__attribute__((used, noinline)) void not_the_entry_point(void) { exit_syscall(1); }

void main(void) { exit_syscall(42); }
