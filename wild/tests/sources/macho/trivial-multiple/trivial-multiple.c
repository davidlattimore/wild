//#Object:runtime.c
//#Object:lib.c
//#ExpectSym:_main
//#TestUpdateInPlace:true
//#DiffIgnore:section.__const
//#DiffIgnore:section.__unwind_info

#include "../common/runtime.h"

int value = 42;

int foo();
long baz() { return value; }

int main() { exit_syscall(foo()); }
