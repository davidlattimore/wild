//#Object:runtime.c
//#DiffEnabled:false
//#Mode:unspecified
//#LinkArgs:-z now -as-needed
//#Shared:symbol-binding-dyn.c
//#Object:symbol-binding-weak.c
//#Object:symbol-binding-strong.c

#include "runtime.h"

// Test that get_non_dynamic correctly selects the strong definition over the
// weak one when the primary definition is from a shared object. The hidden
// visibility forces allow_dynamic=false in symbol lookup, which triggers the
// get_non_dynamic code path.

__attribute__((visibility("hidden"))) int foo(void);
__attribute__((visibility("hidden"))) int bar(void);

void _start(void) {
  runtime_init();

  // foo is defined weakly in symbol-binding-weak.c (returns 1) and strongly in
  // symbol-binding-strong.c (returns 2). Strong should win.
  if (foo() != 2) {
    exit_syscall(foo());
  }

  // bar is defined strongly in symbol-binding-weak.c (returns 10) and weakly in
  // symbol-binding-strong.c (returns 20). Strong should win.
  if (bar() != 10) {
    exit_syscall(bar());
  }

  exit_syscall(42);
}
