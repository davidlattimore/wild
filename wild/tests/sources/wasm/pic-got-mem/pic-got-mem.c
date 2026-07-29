//#CompArgs:-fPIC
//#Object:pic-got-mem2.c

extern int g;

void _start(void) {
  if (g != 7) {
    __builtin_trap();
  }
}
