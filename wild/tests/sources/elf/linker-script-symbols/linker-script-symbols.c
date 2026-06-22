//#Config:default
//#AugmentLinkerScript:script.ld
//#Object:runtime.c
//#ExpectSym:value3 address=0x123
//#ExpectSym:value4 address=0x123

//#Config:lto:default
//#RequiresLinkerPlugin:true
//#SkipLinker:ld
//#LinkerDriver:gcc
//#CompArgs:-flto
//#LinkArgs:-flto -nostdlib -znow
//#DiffIgnore:section.got

//#Config:forward-defs:default
//#SkipLinker:ld
//#LinkerScript:script-forward-defs.ld
//#ExpectError:Symbol 'value5' referenced by linker script does not exist

#include "../common/runtime.h"

int value1 = 100;
int value2 = 200;

extern int value1a;
extern int value2a;
extern int value3;
extern int value4;

int foo(void) { return 9; }
int foo_alias(void);

void _start(void) {
  runtime_init();

  if (foo_alias() != 9) {
    exit_syscall(9);
  }

  if (value1a != 100) {
    exit_syscall(10);
  }

  if (value2 != 200) {
    exit_syscall(11);
  }

  if ((unsigned long)&value3 != (unsigned long)&value4) {
    exit_syscall(12);
  }

  exit_syscall(42);
}
