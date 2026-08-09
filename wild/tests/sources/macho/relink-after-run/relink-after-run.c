//#Object:runtime.c
//#TestRelinkAfterRun:true
//#WildExtraLinkArgs:--threads=3
//#DiffIgnore:section.__unwind_info

#include "../common/runtime.h"

void main(void) { exit_syscall(42); }
