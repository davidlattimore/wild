//#Object:runtime.c
//#ExpectSym:_main
//#TestUpdateInPlace:true
//#DiffIgnore:section.__const
//#DiffIgnore:section.__unwind_info

#include "../common/runtime.h"

void main(void) { exit_syscall(42); }
