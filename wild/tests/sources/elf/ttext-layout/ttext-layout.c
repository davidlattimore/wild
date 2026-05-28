//#AbstractConfig:base
//#Object:../common/runtime.c
//#SkipArch:loongarch64

/* loongarch64: relocation truncated to fit at these address ranges */

//#Config:ttext:base
//#LinkArgs:-Ttext=0x700000 -no-pie
//#ExpectSym:_start address=0x700000

//#Config:tdata:base
//#LinkArgs:-Tdata=0x800000 -no-pie --no-gc-sections
//#ExpectSym:data_var address=0x800000

//#Config:tbss:base
//#LinkArgs:-Tbss=0x900000 -no-pie --no-gc-sections
//#ExpectSym:bss_var address=0x900000

#include "../common/runtime.h"

/* Verify -Tdata places .data at the given address */
__attribute__((used)) int data_var = 1;

/* Verify -Tbss places .bss at the given address */
__attribute__((used)) int bss_var;

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
