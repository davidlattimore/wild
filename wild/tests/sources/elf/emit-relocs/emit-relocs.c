//#Object:runtime.c
//#LinkArgs:--emit-relocs
//#ExpectSection:.rela.text
//#ExpectSym:_start section=".text"
//#ExpectSym:exit_syscall section=".text"
//#DiffIgnore:rel.R_X86_64_PLT32.R_X86_64_PLT32
//#DiffIgnore:rel.R_AARCH64_CALL26.R_AARCH64_CALL26

#include "../common/runtime.h"

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
