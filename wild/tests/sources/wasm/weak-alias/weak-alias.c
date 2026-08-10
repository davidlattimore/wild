//#Object:weak-alias2.c
//#Object:weak-alias3.c

static int dummy(void) { __builtin_trap(); }

int foo(void) __attribute__((weak, alias("dummy")));
int bar(void) __attribute__((weak, alias("dummy")));

void _start(void) {
  if (foo() != 1) {
    __builtin_trap();
  }
  if (bar() != 2) {
    __builtin_trap();
  }
}
