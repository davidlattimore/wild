#include "../common/runtime.h"

const long exit_syscall_num = 1;

void exit_syscall(int exit_code) {
  register long x0 __asm__("x0") = exit_code;
  register long x16 __asm__("x16") = exit_syscall_num;
  __asm__ __volatile__("svc 0x80" : : "r"(x0), "r"(x16) : "memory");
  __builtin_unreachable();
}
