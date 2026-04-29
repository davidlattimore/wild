int foo3(void);

__attribute__((section("foo_calls"))) int call_foo3_custom1(void) {
  return foo3();
}

int padding1(void) { __asm__ __volatile__(".fill 67108864, 1, 0\n"); }

int foo1(void) { return 1; }
int bar1(void) { return 11; }
