//#LinkerScript:linker-script-section-start.ld
//#Object:runtime.c
//#DiffIgnore:segment.LOAD.RW.alignment
// RISC-V: BFD complains about missing __global_pointer$ (defined in the default
// linker script)
//#SkipArch:riscv64
//#ExpectSym:foo address=0x1000000

#include "../common/runtime.h"

__attribute__((used, section(".foo"))) int foo = 7;

void begin_here(void) { exit_syscall(42); }
