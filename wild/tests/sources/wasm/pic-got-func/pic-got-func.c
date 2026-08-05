//#CompArgs:-fPIC
//#Object:pic-got-func2.c

typedef int (*Fn)(void);
int foo(void);

static Fn get_fp(void) { return foo; }

void _start(void) {
  if (get_fp()() != 42) {
    __builtin_trap();
  }
}
