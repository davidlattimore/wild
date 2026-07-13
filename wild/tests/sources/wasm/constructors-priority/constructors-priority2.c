extern int step;

__attribute__((constructor(100))) static void first(void) {
  if (step != 0) {
    __builtin_trap();
  }
  step = 1;
}
