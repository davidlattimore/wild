//#Object:runtime.c
//#Object:lib.c
//#ExpectSym:_main
//#TestUpdateInPlace:true

#include "../common/runtime.h"

int value = 42;

int foo();
long baz() { return value; }

int main() { exit_syscall(foo()); }
