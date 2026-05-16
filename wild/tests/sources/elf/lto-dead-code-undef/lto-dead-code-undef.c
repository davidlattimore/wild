// Tests that we don't error if there's an undefined symbol in dead code, when the dead code isn't
// referenced from outside the IR.

//#AbstractConfig:default
//#Object:runtime.c
//#RequiresLinkerPlugin:true
//#CompArgs:-flto -O1

//#Config:gcc:default
//#LinkerDriver:gcc
//#Object:lto-dead-code-undef-1.c
//#LinkArgs:-flto -O1 -nostdlib
//#DiffIgnore:section.rodata
//#DiffIgnore:section.got

#include "../common/runtime.h"

int foo(int x);

void _start(void) {
  runtime_init();
  exit_syscall(foo(0));
}
