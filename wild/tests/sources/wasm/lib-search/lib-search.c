//#Archive:template(-L$OUT_DIR -lfoo):libfoo.c

extern int from_lib(void);

void _start(void) {
  if (from_lib() != 42) {
    __builtin_trap();
  }
}
