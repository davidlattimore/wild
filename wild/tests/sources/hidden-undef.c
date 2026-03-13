// Tests that linking fails when a hidden symbol is only available from a DSO.

//#Object:runtime.c
//#Mode:dynamic
//#RunEnabled:false
//#Shared:hidden-undef-lib.c
//#ExpectError:foo

#include "runtime.h"

// foo is declared hidden — must not be resolved from the DSO above.
__attribute__((visibility("hidden"))) int foo(void);

void _start(void) {
  runtime_init();
  exit_syscall(foo());
}
