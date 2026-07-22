static int x;

__attribute__((constructor(100))) static int init(void) {
  x = 42;
  return 0;
}

void _start(void) {
  if (x != 42) {
    __builtin_trap();
  }
}
