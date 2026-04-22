//#LinkArgs:-T ./script-sort.ld

__attribute__((used, section(".text.func_c"))) int func_c() { return 3; }

__attribute__((used, section(".text.func_a"))) int func_a() { return 1; }

__attribute__((used, section(".text.func_b"))) int func_b() { return 2; }

__attribute__((naked)) void _start() {
  asm volatile(
      "mov $60, %rax\n"
      "mov $42, %rdi\n"
      "syscall\n");
}
