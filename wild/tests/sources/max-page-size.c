//#AbstractConfig:default
//#Object:runtime.c
//#DiffIgnore:section.data
//#DiffIgnore:section.rodata.alignment

//#Config:64k:default
//#LinkArgs:-z max-page-size=65536 -z now
//#ExpectLoadAlignment:0x10000

//#Config:1m:default
//#LinkArgs:-z max-page-size=0x100000 -z now
//#ExpectLoadAlignment:0x100000
// It seems that large page sizes are not permitted in RISC-V QEMU
//#Arch: x86_64,aarch64

//#Config:2m:default
//#LinkArgs:-z max-page-size=0x200000 -z now
//#ExpectLoadAlignment:0x200000
// It seems that large page sizes are not permitted in RISC-V QEMU
//#Arch: x86_64,aarch64

#include "runtime.h"

int _start() {
  runtime_init();
  exit_syscall(42);
}
