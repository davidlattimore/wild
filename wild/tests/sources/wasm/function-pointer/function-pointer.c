static int inc(int x) { return x + 1; }

typedef int (*Fn)(int);

void _start(void) {
  Fn f = inc;
  if (f(1) != 2) {
    __builtin_trap();
  }
}
