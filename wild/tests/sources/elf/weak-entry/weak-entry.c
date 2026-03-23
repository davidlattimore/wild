//#Object:runtime.c
//#Object:weak-entry-1.c

#include "runtime.h"

#define WEAK __attribute__((weak))

void WEAK _start(void) {
  runtime_init();
  exit_syscall(5);
}
