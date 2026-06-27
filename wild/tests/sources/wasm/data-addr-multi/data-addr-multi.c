//#Object:data-addr-multi2.c

extern int value;
int* ptr = &value;

void _start(void) {
  if (*ptr != 42) {
    __builtin_trap();
  }
}
