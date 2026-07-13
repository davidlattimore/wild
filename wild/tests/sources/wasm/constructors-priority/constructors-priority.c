//#Object:constructors-priority2.c

int step;

__attribute__((constructor(200))) static void second(void) {
  if (step != 1) {
    __builtin_trap();
  }
  step = 2;
}

void _start(void) {
  if (step != 2) {
    __builtin_trap();
  }
}
