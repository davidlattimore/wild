//#LinkerScript:linker-script-executable.ld
//#Object:runtime.c
//#DiffIgnore: segment.LOAD.RW.alignment
// RISC-V: BFD complains about missing __global_pointer$ (defined in the default
// linker script)
//#Arch:x86_64,aarch64

#include <stddef.h>

#include "runtime.h"

int value = 42;
extern const char start_of_text;
extern const char start_of_data;
extern const char start_of_512;

void begin_here(void) {
  if ((size_t)&start_of_text != 0x600000) {
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
