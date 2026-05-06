//#Object:runtime.c
//#ExpectSym:_main
//#TestUpdateInPlace:true
//#RunEnabled: false

#include "../common/runtime.h"

void main(void) { exit_syscall(42); }
