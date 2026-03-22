#include "runtime.h"

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
