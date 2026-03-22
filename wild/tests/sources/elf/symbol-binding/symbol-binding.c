//#Object:runtime.c
//#DiffEnabled:false
//#Mode:unspecified
//#LinkArgs:-z now -as-needed
//#SkipLinker:ld
//#Shared:symbol-binding-dyn.c
//#Object:symbol-binding-1.c
//#Archive:symbol-binding-2.c

#include "runtime.h"

__attribute__((visibility("hidden"))) int foo(void);
__attribute__((visibility("hidden"))) int bar(void);

void _start(void) {
  runtime_init();

  if (foo() != 2) {
    exit_syscall(foo());
  }

  if (bar() != 10) {
    exit_syscall(bar());
  }

  exit_syscall(42);
}
