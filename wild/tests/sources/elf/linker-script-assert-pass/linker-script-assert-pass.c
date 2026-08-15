//#LinkArgs:-T ./linker-script-assert-pass.ld
//#RunEnabled:false
//#DiffEnabled:false
//#Object:runtime.c
// RISC-V: BFD complains about missing __global_pointer$ (defined in the default linker script)
//#SkipArch:riscv64
//#ExpectSym:symbol10 section=".data",offset-in-section=0x10040
//#ExpectSym:symbol11 address=0x80
//#ExpectSym:symbol10_assert section=".data",offset-in-section=1
//#ExpectSym:symbol11_assert address=0x1

#include "../common/runtime.h"

int symbol4 = 0x4000;
int symbol6 __attribute__((weak));
int symbol7 __attribute__((weak)) = 0x7000;
extern int symbol8 __attribute__((weak));

void _start() { exit_syscall(symbol4 + symbol6 + symbol7 + symbol8); }
