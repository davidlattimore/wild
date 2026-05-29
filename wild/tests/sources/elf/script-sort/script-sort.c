//#Object:runtime.c
//#Object:script-sort-2.c

#include "../common/runtime.h"

__attribute__((used, section(".text.func_a"))) int func_a() { return 1; }

extern int func_b();

__attribute__((used, section(".text.func_c"))) int func_c() { return 3; }

extern int func_kept() __attribute__((weak));

void _start(void) {
  runtime_init();

  unsigned long a_addr = (unsigned long)&func_a;
  unsigned long b_addr = (unsigned long)&func_b;
  unsigned long c_addr = (unsigned long)&func_c;
  unsigned long kept_addr = (unsigned long)&func_kept;

  if (a_addr >= c_addr) {
    exit_syscall(101);
  }

  if (b_addr >= kept_addr) {
    exit_syscall(102);
  }

  if (kept_addr == 0) {
    exit_syscall(103);
  }
  exit_syscall(42);
}
