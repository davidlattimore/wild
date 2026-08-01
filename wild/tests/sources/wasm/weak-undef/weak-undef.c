//#Object:weak-undef2.c
//#DoesNotContain: env

__attribute__((weak)) int foo(int x);

extern int other_uses_foo(void);

void _start(void) {
  if (foo) {
    if (foo(1) != 2) {
      __builtin_trap();
    }
  }
  if (other_uses_foo() != 0) {
    __builtin_trap();
  }
}
