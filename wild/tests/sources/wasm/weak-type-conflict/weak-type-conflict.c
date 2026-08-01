//#Object:weak-type-conflict2.c
//#ExpectError:conflict_fn

__attribute__((weak)) int conflict_fn(int x);

void _start(void) {
  if (conflict_fn) {
    (void)conflict_fn(1);
  }
}
