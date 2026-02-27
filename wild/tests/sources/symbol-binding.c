//#Object:runtime.c
//#Object:symbol-binding-weak.c
//#Object:symbol-binding-strong.c

#include "runtime.h"

// Test that when multiple regular object files define the same symbol, the
// strong definition is chosen over the weak one, regardless of link order.
// symbol-binding-weak.c is listed before symbol-binding-strong.c, but the
// strong definition should still win.

int foo(void);
int bar(void);

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
