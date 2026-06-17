//#LinkArgs: -T tests/sources/elf/script-sort/script-sort.ld
//#Object:runtime.c
//#Object:script-sort-2.c
//#Object:script-sort-3.c
//#EnableLinker:lld
//#DiffMatchAny:true

#include "../common/runtime.h"

extern int func_a();
extern int func_b();
extern int func_c();

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
  runtime_init();

  unsigned long a_addr = (unsigned long)&func_a;
  unsigned long b_addr = (unsigned long)&func_b;
  unsigned long c_addr = (unsigned long)&func_c;

  if (a_addr >= b_addr) {
    exit_syscall(101);
  }
  if (b_addr >= c_addr) {
    exit_syscall(102);
  }

  if (func_a() != 1 || func_b() != 2 || func_c() != 3) {
    exit_syscall(103);
  }

  exit_syscall(42);
}
