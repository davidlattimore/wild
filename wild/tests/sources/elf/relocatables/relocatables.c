//#EnableLinker:lld
//#Object:runtime.c
//#Relocatable:relocatable-1.c,relocatable-2.c

#include "runtime.h"

int add(int, int);
int subtract(int, int);
int multiply(int, int);

void _start(void) {
  runtime_init();

  if (add(3, 4) != 7) {
    exit_syscall(1);
  }
  if (subtract(10, 3) != 7) {
    exit_syscall(2);
  }
  if (multiply(3, 4) != 12) {
    exit_syscall(3);
  }
  exit_syscall(42);
}
