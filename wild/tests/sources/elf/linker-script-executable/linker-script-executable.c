//#Config:default
//#LinkerScript:linker-script-executable.ld
//#Object:runtime.c
//#DiffIgnore: segment.LOAD.RW.alignment
// RISC-V: BFD complains about missing __global_pointer$ (defined in the default linker script)
//#SkipArch:riscv64

//#Config:no_gc_sections:default
//#LinkArgs:--no-gc-sections

//#Config:check_start
//#LinkerScript:linker-script-executable.ld
//#LinkerScript:linker-script-check-start.ld
//#Object:runtime.c
// .text is the first section in ld, so this test wouldn't work with ld.
//#ReferenceLinkers:

#include <stddef.h>

#include "../common/runtime.h"

int value = 42;
extern const char start_of_sections;
extern const char start_of_data;
extern const char start_of_512;

void begin_here(void) {
  if ((size_t)&start_of_sections != 0x600000) {
    exit_syscall(10);
  }

  if ((size_t)&start_of_data != 0x800000) {
    exit_syscall(11);
  }

  if ((size_t)&start_of_512 & 511 != 0) {
    exit_syscall(12);
  }

  exit_syscall(value);
}
