//#AbstractConfig:default
//#RequiresLinkerPlugin:true
//#Object:runtime.c
//#Object:wrap-lto-real-def.c:-flto
//#Object:wrap-lto-real-wrap.c
//#ReferenceLinkers:
//#LinkArgs:-flto -nostdlib -z now -Wl,-wrap,foo
//#DiffIgnore:rel.R_X86_64_PC32.R_X86_64_PC32
//#DiffIgnore:rel.R_AARCH64_CALL26.R_AARCH64_CALL26

//#Config:gcc:default
//#LinkerDriver:gcc

//#Config:clang:default
//#Compiler:clang
//#LinkerDriver:clang
//#ReferenceLinkers:lld

#include "../common/runtime.h"

int foo(void);

void _start(void) {
  runtime_init();
  if (foo() != 42) {
    exit_syscall(100);
  }
  exit_syscall(42);
}
