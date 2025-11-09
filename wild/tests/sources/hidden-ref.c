// Tests behaviour when we reference via a hidden symbol.

//#AbstractConfig:default
//#Object:runtime.c
//#DiffEnabled:false
//#Mode:unspecified
//#LinkArgs:-z now -as-needed

//#Config:object:default
//#Shared:hidden-ref-1.c
//#Object:hidden-ref-2.c

//#Config:archive:default
//#Shared:hidden-ref-1.c
//#Archive:hidden-ref-2.c

#include "runtime.h"

__attribute__((visibility(("hidden")))) int foo(void);

void _start(void) {
  runtime_init();

  if (foo() != 2) {
    exit_syscall(20);
  }

  exit_syscall(42);
}
