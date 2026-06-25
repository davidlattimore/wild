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

//#Config:fat-object-64:default
//#FatObject64:fat-1.c
// LLD (as of 22.1.6) doesn't seem to support 64 bit fat inputs.
//#ReferenceLinkers:

//#Config:fat-archive-64:default
//#FatArchive64:fat-1.c
// LLD (as of 22.1.6) doesn't seem to support 64 bit fat inputs.
//#ReferenceLinkers:

#include "../common/runtime.h"

int aux(void);

void main(void) { exit_syscall(aux()); }
