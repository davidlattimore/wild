static int x;

__attribute__((constructor(100))) static void init(void) { x = 42; }

void _start(void) {
  if (x != 42) {
    __builtin_trap();
  }
}
