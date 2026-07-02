//#Config:default
//#LinkerScript:linker-script-location-counter.ld
//#LinkerScript:linker-script-location-counter-2.ld
//#LinkerScript:linker-script-location-counter-3.ld
//#Object:runtime.c
// RISC-V: BFD complains about missing __global_pointer$ (defined in the default linker script)
//#SkipArch:riscv64,ppc64le

//#Config:no_gc_sections:default
//#LinkArgs:--no-gc-sections

//#Config:underflow
//#Object:runtime.c
//#LinkerScript:linker-script-location-counter-underflow.ld
//#ExpectError:(?i)cannot move location counter backwards

#include <stddef.h>

#include "../common/runtime.h"

int ret = 42;

void begin_here(void) { exit_syscall(ret); }
