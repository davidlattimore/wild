//#Object:runtime.c
//#SkipLinker:ld
//#DriverMode:save-dir-response

#include "../common/runtime.h"

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
