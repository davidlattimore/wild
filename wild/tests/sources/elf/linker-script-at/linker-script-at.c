//#LinkerScript:linker-script-at.ld
//#Object:runtime.c
// RISC-V: BFD complains about missing __global_pointer$ (defined in the default linker script)
//#SkipArch:riscv64
//#ExpectProgramHeader:LOAD flags=RX,sections=[.text,*],paddr=0x200000,vaddr=0x100000
//#ExpectProgramHeader:LOAD flags=RW,sections=[.data,*],paddr=0x300000,vaddr=0x200000

#include "../common/runtime.h"

int foo = 42;

int main(void) { exit_syscall(foo); }
