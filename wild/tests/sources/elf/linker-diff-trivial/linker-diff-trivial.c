//#AbstractConfig:default
//#Object:runtime.c

//#Config:malfunction-elf-incorrect-type:default
//#Malfunction:elf-incorrect-type
//#Arch:x86_64

#include "../common/runtime.h"

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
