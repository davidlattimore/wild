// Disallow linking against shared object that doesn't provide our required
// symbol by itself, but depends on another shared object providing that symbol.

//#AbstractConfig:default
//#Object:runtime.c
//#Mode:dynamic

//#Config:object-first:default
//#Object:undef-transitive-1.c
//#Shared:undef-transitive-2.c
//#ExpectError:foo

//#Config:shlib-first:default
//#Shared:undef-transitive-2.c
//#Object:undef-transitive-1.c
//#ExpectError:foo

#include "runtime.h"

int bar(void);

void _start(void) {
  runtime_init();
  exit_syscall(bar());
}
