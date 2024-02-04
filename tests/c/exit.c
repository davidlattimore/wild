#include "exit.h"

#include <inttypes.h>
#include <sys/types.h>

void exit_syscall(int exit_code) {
    register int64_t rax __asm__ ("rax") = 60;
    register int rdi __asm__ ("rdi") = exit_code;
    __asm__ __volatile__ (
        "syscall"
        : "+r" (rax)
        : "r" (rdi)
        : "rcx", "r11", "memory"
    );
}
