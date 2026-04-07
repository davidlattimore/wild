//#Object:undefined-weak-and-strong1.c
//#ExpectError:foo
//#Ignore:undefined symbol enforcement not yet implemented for Mach-O

void __attribute__((weak)) foo(void);
void call_foo(void);
int main() {
  if (foo) foo();
  call_foo();
  return 42;
}
