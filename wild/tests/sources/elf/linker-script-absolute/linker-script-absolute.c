//#ReferenceLinkers:bfd
//#Object:runtime.c
//#LinkerScript:linker-script-absolute.ld
//#SkipArch:riscv64
//#ExpectSym:absolute_plus address=24
//#ExpectSym:abs_lnot address=0
//#ExpectSym:abs_land section=".text"
//#ExpectSym:abs_lor section=".text"

#include "../common/runtime.h"

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
