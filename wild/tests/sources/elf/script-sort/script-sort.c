//#Object:runtime.c
//#Object:script-sort-2.c

#include "../common/runtime.h"

__attribute__((used, section(".text.sort.a"))) int func_a() { return 1; }

extern int func_b();

__attribute__((used, section(".text.sort.c"))) int func_c() { return 3; }

void _start(void) {
  runtime_init();

  unsigned long a_addr = (unsigned long)&func_a;
  unsigned long b_addr = (unsigned long)&func_b;
  unsigned long c_addr = (unsigned long)&func_c;

  if (a_addr >= c_addr) {
    exit_syscall(101);
  }

  exit_syscall(42);
}
