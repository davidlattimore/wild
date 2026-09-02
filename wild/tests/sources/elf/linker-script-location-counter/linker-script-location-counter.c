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

//#Config:symbols
//#LinkerScript:linker-script-location-counter-symbols.ld
//#LinkArgs:--defsym=offset4=0x300
//#Object:runtime.c
// RISC-V: BFD complains about missing __global_pointer$ (defined in the default linker script)
//#SkipArch:riscv64,ppc64le
//#DiffIgnore:segment.LOAD.RX.alignment
//#DiffIgnore:segment.LOAD.RWX.alignment

//#Config:earlier_section_symbol
//#Arch:x86_64
//#LinkerScript:linker-script-earlier-section-symbol.ld
//#Object:runtime.c
//#RunEnabled:false

//#Config:object_symbol_offset
//#LinkerScript:linker-script-object-symbol-offset.ld
//#Object:runtime.c
//#Object:object-symbol-prefix.c
//#Object:object-symbol-target.c
// RISC-V: BFD complains about missing __global_pointer$ (defined in the default linker script)
//#SkipArch:riscv64,ppc64le
//#DiffIgnore:segment.LOAD.RX.alignment
//#DiffIgnore:segment.LOAD.RWX.alignment

//#Config:mixed_symbol_kinds
//#Arch:x86_64
//#ReferenceLinkers:bfd,lld
//#LinkerScript:linker-script-mixed-symbol-kinds.ld
//#Object:runtime.c
//#RunEnabled:false
//#DiffIgnore:segment.LOAD.RX.alignment
//#DiffIgnore:segment.LOAD.RWX.alignment

//#Config:symbol_with_unrelated_sort
//#ReferenceLinkers:bfd,lld
//#LinkerScript:linker-script-symbol-sort.ld
//#Object:runtime.c
//#RunEnabled:false
// RISC-V: BFD complains about missing __global_pointer$ (defined in the default linker script)
//#SkipArch:riscv64,ppc64le
//#DiffIgnore:segment.LOAD.RX.alignment
//#DiffIgnore:segment.LOAD.RWX.alignment

//#Config:symbol_only_reference
//#Arch:x86_64
//#ReferenceLinkers:lld
//#LinkerScript:linker-script-symbol-only-reference.ld
//#Object:runtime.c
//#Object:location-counter-only-symbol.c
//#RunEnabled:false
//#DiffIgnore:segment.LOAD.RX.alignment
//#DiffIgnore:segment.LOAD.RWX.alignment

//#Config:cyclic_symbol
//#LinkerScript:linker-script-location-counter-cyclic-symbol.ld
//#ReferenceLinkers:bfd,lld
//#Object:runtime.c
// RISC-V: BFD complains about missing __global_pointer$ (defined in the default linker script)
//#SkipArch:riscv64,ppc64le
// The binary created is not valid, so we can't run it.
//#RunEnabled:false

#include <stddef.h>

#include "../common/runtime.h"

int ret = 42;

__attribute__((section(".foo.first"))) int data_first = 1;
__attribute__((section(".foo.second"), aligned(8))) int data_second = 2;

__attribute__((section(".text.foo"))) void foo(void) {}

__attribute__((section(".custom.1"))) void custom_one(void) {}
__attribute__((section(".custom.2"))) void custom_two(void) {}
__attribute__((section(".custom.3"))) void custom_three(void) {}

__attribute__((section(".sort.b"), used)) void sort_b(void) {}
__attribute__((section(".sort.a"), used)) void sort_a(void) {}
__attribute__((section(".sort.c"), used)) void sort_c(void) {}

__asm__(".global abs_symbol\n.set abs_symbol, 0x1000000\n");
__asm__(".global abs_between\n.set abs_between, 0x650000\n");
__asm__(".global abs_small\n.set abs_small, 5\n");

void begin_here(void) {
  foo();
  custom_one();
  custom_two();
  custom_three();
  exit_syscall(ret);
}
