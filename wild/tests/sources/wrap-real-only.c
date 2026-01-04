//#Object:runtime.c
//#Object:wrap-real-only2.c
//#LinkArgs:--wrap=foo

#include "runtime.h"

// Note that `__wrap_foo` is not defined anywhere.
int __real_foo(void);

void _start(void) {
  runtime_init();

  // `__real_foo` should resolve to the original `foo`
  if (__real_foo() != 123) {
    exit_syscall(100);
  }

  exit_syscall(42);
}
