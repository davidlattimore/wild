//#CompArgs:-fPIC

static int f(void) { return 1; }

typedef int (*Fn)(void);

void _start(void) {
  Fn p = f;
  if (p() != 1) {
    __builtin_trap();
  }
}
