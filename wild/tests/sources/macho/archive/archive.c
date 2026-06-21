//#Object:runtime.c
//#Archive:from_archive.c
//#ExpectSym:_main
//#DiffIgnore:section.__const
//#DiffIgnore:section.__unwind_info

#include "../common/runtime.h"

int from_archive(void);

void main(void) { exit_syscall(from_archive()); }
