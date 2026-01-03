#include <inttypes.h>
#include <sys/types.h>

#ifdef __sun
#define EXIT_SYSCALL 1
#else
#define EXIT_SYSCALL 60
#endif

#if defined(__x86_64__)
void exit_syscall(int exit_code) {
  register int64_t rax __asm__("rax") = EXIT_SYSCALL;
  register int rdi __asm__("rdi") = exit_code;
  __asm__ __volatile__("syscall"
                       : "+r"(rax)
                       : "r"(rdi)
                       : "rcx", "r11", "memory");
}
#elif defined(__aarch64__)
void exit_syscall(int exit_code) {
  register long w8 __asm__("w8") = 93;
  register long x0 __asm__("x0") = exit_code;
  __asm__ __volatile__("svc 0" : "=r"(x0) : "r"(w8) : "cc", "memory");
}
#elif defined(__riscv)
void exit_syscall(int exit_code) {
  register long a7 __asm__("a7") = 93;
  register long a0 __asm__("a0") = exit_code;
  __asm__ __volatile__("ecall"
                       : /* no output */
                       : "r"(a7), "r"(a0)
                       : "memory");
}
#elif defined(__loongarch64)
void exit_syscall(int exit_code) {
  register long a7 __asm__("$a7") = 93;
  register long a0 __asm__("$a0") = exit_code;
  __asm__ __volatile__("syscall 0"
                       : /* no output */
                       : "r"(a7), "r"(a0)
                       : "memory");
}
#endif
