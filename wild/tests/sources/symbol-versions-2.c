#define SYMVER(a, b) __asm__(".symver " a "," b)

SYMVER("foo_v1", "foo@1.0");
SYMVER("foo_v2", "foo@@2.0");

int foo_v1(void) { return 1; }

int foo_v2(void) { return 2; }
