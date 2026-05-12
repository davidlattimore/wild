// Tests that we're able to report the line number of an undefined symbol
// reference using debug info.

//#AbstractConfig:default
//#Object:runtime.c
//#ExpectError:source-info-from-debug.*27

//#Config:non-lto:default
//#CompArgs:-g
// GNU ld reports incorrect line numbers.
//#SkipLinker:ld

//#Config:lto:default
//#RequiresLinkerPlugin:true
//#LinkerDriver:gcc
//#CompArgs:-g -flto -fPIC
//#LinkArgs:-flto -nostdlib -fPIC
// GNU ld tries to generate a PLT, then errors
//#SkipLinker:ld

#include "../common/runtime.h"

void foo(void);

void _start(void) {
  runtime_init();
  foo();
  exit_syscall(42);
}
