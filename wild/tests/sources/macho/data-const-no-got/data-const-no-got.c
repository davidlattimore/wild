//#Object:runtime.c
//#DiffIgnore:section.__unwind_info
//#ExpectSym:_value section="__custom",segment="__DATA_CONST"
//#NoSection:__got

#include "../common/runtime.h"

__attribute__((section("__DATA_CONST,__custom"))) volatile const long value = 1;

void main(void) { exit_syscall(42); }
