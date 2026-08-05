//#Object:runtime.c
//#ExpectSym:_main section="__text"
//#ExpectSym:_exit_syscall_num section="__const"
//#NoSection:__cstring
//#NoSection:__stubs
//#TestUpdateInPlace:true
//#DiffIgnore:section.__unwind_info

#include "../common/runtime.h"

void main(void) { exit_syscall(42); }
