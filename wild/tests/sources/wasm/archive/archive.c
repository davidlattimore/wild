//#Archive:archive2.c

extern int archived_value;

void _start(void) {
  if (archived_value != 7) {
    __builtin_trap();
  }
}
