//#Object:runtime.c
//#ExpectSym:_first section="__first",segment="__CUSTOM1"
//#ExpectSym:_second section="__second",segment="__CUSTOM1"
//#ExpectSym:_third section="__third",segment="__CUSTOM2"
//#DiffIgnore:section.__unwind_info

#include "../common/runtime.h"

__attribute__((section("__CUSTOM1,__first"))) long first = 10;
__attribute__((section("__CUSTOM1,__second"))) long second = 11;
__attribute__((section("__CUSTOM2,__third"))) long third = 21;

void main(void) { exit_syscall(first + second + third); }
