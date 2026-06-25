//#AbstractConfig:default
//#RequiresLinkerPlugin:true
//#Object:runtime.c
//#Object:wrap-lto-2.c:-fno-lto
//#ReferenceLinkers:
//#CompArgs:-flto
//#LinkArgs:-flto -nostdlib -z now -Wl,-wrap,foo

//#Config:gcc:default
//#LinkerDriver:gcc

//#Config:clang:default
//#Compiler:clang
//#LinkerDriver:clang
//#ReferenceLinkers:lld

#include "../common/runtime.h"

int foo(void);
int __real_foo(void);

int __wrap_foo(void) { return __real_foo() + 32; }

void _start(void) {
  runtime_init();
  if (foo() != 42) {
    exit_syscall(100);
  }
  exit_syscall(42);
}
