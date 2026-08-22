//#Config:default
//#LinkerScript:linker-script-location-counter.ld
//#LinkerScript:linker-script-location-counter-2.ld
//#LinkerScript:linker-script-location-counter-3.ld
//#Object:runtime.c
// RISC-V: BFD complains about missing __global_pointer$ (defined in the default linker script)
//#SkipArch:riscv64,ppc64le

//#Config:phdrs
//#LinkerScript:linker-script-location-counter-phdrs.ld
//#Object:runtime.c
// RISC-V: BFD complains about missing __global_pointer$ (defined in the default linker script)
//#SkipArch:riscv64,ppc64le

//#Config:single_location_counter
//#LinkerScript:linker-script-single-location-counter.ld
//#Object:runtime.c
// RISC-V: BFD complains about missing __global_pointer$ (defined in the default linker script)
//#SkipArch:riscv64,ppc64le

//#Config:no_gc_sections:default
//#LinkArgs:--no-gc-sections

//#Config:section_sizeof
//#LinkerScript:linker-script-section-sizeof.ld
//#Object:runtime.c
// RISC-V: BFD complains about missing __global_pointer$ (defined in the default linker script)
//#SkipArch:riscv64,ppc64le

//#Config:underflow
//#Object:runtime.c
//#LinkerScript:linker-script-location-counter-underflow.ld
//#ExpectError:(?i-u)cannot move location counter backwards

//#Config:lc_after_section
//#LinkerScript:linker-script-lc-after-section.ld
//#Object:runtime.c
// RISC-V: BFD complains about missing __global_pointer$ (defined in the default linker script)
//#SkipArch:riscv64,ppc64le
//#DiffIgnore:segment.LOAD.RX.alignment
//#DiffIgnore:segment.LOAD.RWX.alignment

#include <stddef.h>

#include "../common/runtime.h"

int ret = 42;

__attribute__((section(".foo.first"))) int data_first = 1;
__attribute__((section(".foo.second"), aligned(8))) int data_second = 2;

__attribute__((section(".text.foo"))) void foo(void) {}

void begin_here(void) {
  foo();
  exit_syscall(ret);
}
