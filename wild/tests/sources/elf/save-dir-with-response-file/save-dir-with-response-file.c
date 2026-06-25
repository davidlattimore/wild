//#Object:runtime.c
//#ReferenceLinkers:
//#DriverMode:save-dir-response

#include "../common/runtime.h"

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
