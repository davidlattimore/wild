//#Object:runtime.c

#include "runtime.h"

#define ALIGNMENT 65536

struct __attribute__((aligned(ALIGNMENT))) S {
  short f[3];
};
struct S object;

void _start(void) {
  runtime_init();

  void* ptr = &object;
  if ((unsigned long long)ptr & (ALIGNMENT - 1)) {
    exit_syscall(10);
  }

  exit_syscall(42);
}
