// Tests that GOT references to local (static) functions work correctly.
// The compiler may generate GOT-indirect references for function pointers.

static int local_fn1(void) { return 20; }
static int local_fn2(void) { return 22; }

typedef int (*fnptr)(void);

// Force GOT-indirect references by taking addresses in a volatile context.
int main() {
  volatile fnptr f1 = local_fn1;
  volatile fnptr f2 = local_fn2;
  return f1() + f2();
}
