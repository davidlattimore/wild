//#ReferenceLinkers:bfd
//#Object:runtime.c
//#LinkerScript:linker-script-absolute.ld
//#SkipArch:riscv64

#include "../common/runtime.h"

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
