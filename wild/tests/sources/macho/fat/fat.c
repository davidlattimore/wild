//#AbstractConfig:default
//#Object:runtime.c
//#DiffIgnore:section.__const
//#DiffIgnore:section.__unwind_info
// TODO: Add support for fat objects to linker-diff.
//#DiffEnabled:false

//#Config:fat-object:default
//#FatObject:fat-1.c

//#Config:fat-archive:default
//#FatArchive:fat-1.c

#include "../common/runtime.h"

int aux(void);

void main(void) { exit_syscall(aux()); }
