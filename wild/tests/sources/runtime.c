#include "runtime.h"

#include <inttypes.h>
#include <sys/types.h>

// On RISC-V, the GP register needs to point to the symbol `__global_pointer$`.
// See
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

// TODO: Move contents of exit.c here. Avoiding doing that for now to avoid
// merge conflicts.
#include "exit.c"