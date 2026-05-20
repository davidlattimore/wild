// Tests that symbol aliases via --defsym and from linker scripts (a) trigger loading of archive
// entries and (b) prevent garbage collection of the target symbol.

//#AbstractConfig:default
//#Object:runtime.c

//#Config:defsym-obj:default
//#Object:obj1.c
//#LinkArgs:--defsym=bar=foo

//#Config:script-obj:default
//#AugmentLinkerScript:script.ld
//#Object:obj1.c

//#Config:defsym-archive:default
//#Archive:obj1.c
//#LinkArgs:--defsym=bar=foo

//#Config:script-archive:default
//#AugmentLinkerScript:script.ld
//#Archive:obj1.c

#include "../common/runtime.h"

int bar(void);

void _start(void) {
  runtime_init();
  if (bar() != 10) {
    exit_syscall(10);
  }
  exit_syscall(42);
}
