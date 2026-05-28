#include "../common/runtime.h"

__attribute__((used, section(".text.func_c"))) int func_c() { return 3; }

__attribute__((used, section(".text.func_a"))) int func_a() { return 1; }

__attribute__((used, section(".text.func_b"))) int func_b() { return 2; }

void _start(void) {
  runtime_init();

  exit_syscall(42);
}
