//#AbstractConfig:default
//#Object:runtime.c

//#Config:no-gc:default
//#LinkArgs:-z now --no-gc-sections
//#DiffIgnore: segment.LOAD.RW.alignment

// With --gc-sections enabled, all code gets eliminated and there's nothing to run. If we try to
// execute this binary, it will segfault, so we don't.
//#Config:gc:default
//#LinkArgs:-z now --gc-sections
//#RunEnabled:false

#include "runtime.h"

// Provided this is the first function, it'll get used as the entry point - at least by GNU ld. LLD
// doesn't set an entry point in this case.
void this_is_the_entry_point(void) {
    exit_syscall(42);
}
