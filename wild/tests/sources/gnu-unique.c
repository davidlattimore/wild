//#Object:runtime.c
//#Object:gnu-unique-1.cc
//#Object:gnu-unique-2.cc

#include "runtime.h"

typedef int (*get_int_fn_t)(int);

// Each of these functions instantiates the same template with the same type.
// The template contains a static variable that is incremented each time it's
// called. GCC will emit this static as STB_GNU_UNIQUE in order to ensure that
// there's only a single instance of it.
get_int_fn_t get_fn1(void);
get_int_fn_t get_fn2(void);

void _start(void) {
  runtime_init();

  // 10 + 1 == 1
  if (get_fn1()(10) != 11) {
    exit_syscall(11);
  }

  // 10 + 2 = 17
  if (get_fn2()(15) != 17) {
    exit_syscall(12);
  }

  exit_syscall(42);
}
