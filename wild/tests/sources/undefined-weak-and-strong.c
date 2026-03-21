// Verifies that we error when there's a strong reference to an undefined symbol
// even if we previously encountered a weak reference.

//#CompArgs:-ffunction-sections
//#LinkArgs:--gc-sections
//#Object:undefined-weak-and-strong-1.c
//#ExpectError:foo

void __attribute__((weak)) foo(void);

void call_foo(void);

void _start(void) {
  foo();
  call_foo();
}
