int value = 42;
int* ptr = &value;

void _start(void) {
  if (*ptr != 42) {
    __builtin_trap();
  }
}
