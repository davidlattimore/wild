#include "../common/runtime.h"

#include <inttypes.h>
#include <sys/types.h>

#ifdef __sun
#define EXIT_SYSCALL 1
#else
#define EXIT_SYSCALL 60
#endif

// On RISC-V, the GP register needs to point to the symbol `__global_pointer$`. See
// https://www.sifive.com/blog/all-aboard-part-3-linker-relaxation-in-riscv-toolchain
#if defined(__riscv)
void runtime_init(void) {
  __asm__ __volatile__(
      ".option push\n\
        .option norelax\n\
        la gp, __global_pointer$\n\
        .option pop");
}
#else
void runtime_init(void) {}
#endif

#if defined(__x86_64__)
void exit_syscall(int exit_code) {
  register int64_t rax __asm__("rax") = EXIT_SYSCALL;
  register int rdi __asm__("rdi") = exit_code;
  __asm__ __volatile__("syscall" : "+r"(rax) : "r"(rdi) : "rcx", "r11", "memory");
}
#elif defined(__aarch64__)
void exit_syscall(int exit_code) {
  register long w8 __asm__("w8") = 93;
  register long x0 __asm__("x0") = exit_code;
  __asm__ __volatile__("svc 0" : "+r"(x0) : "r"(w8) : "cc", "memory");
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
#elif defined(__powerpc64__)
void exit_syscall(int exit_code) {
  register long r0 __asm__("r0") = 1;  // __NR_exit
  register long r3 __asm__("r3") = exit_code;
  __asm__ __volatile__("sc" : "+r"(r3) : "r"(r0) : "memory");
}
#endif

#if defined(__powerpc64__)
// Unlike the other targets, gcc on ppc64le lowers large aggregate initialisers to a call to
// memcpy even at -O0, and these freestanding tests don't link libc. Provide a minimal
// implementation. At -O0 gcc doesn't run loop-idiom recognition, so this byte loop is not turned
// back into a memcpy call (verified by disassembly).
void* memcpy(void* dest, const void* src, __SIZE_TYPE__ n) {
  char* d = dest;
  const char* s = src;
  for (__SIZE_TYPE__ i = 0; i < n; i++) {
    d[i] = s[i];
  }
  return dest;
}
#endif
