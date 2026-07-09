static int step;

__attribute__((constructor(200))) static void second(void) {
  if (step != 1) {
    __builtin_trap();
  }
  step = 2;
}

__attribute__((constructor(100))) static void first(void) {
  if (step != 0) {
    __builtin_trap();
  }
  step = 1;
}

void _start(void) {
  if (step != 2) {
    __builtin_trap();
  }
}
