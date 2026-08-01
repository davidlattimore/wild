//#Object:weak-def2.c

__attribute__((weak)) int foo(int x);

void _start(void) {
  if (!foo) {
    __builtin_trap();
  }
  if (foo(1) != 2) {
    __builtin_trap();
  }
}
