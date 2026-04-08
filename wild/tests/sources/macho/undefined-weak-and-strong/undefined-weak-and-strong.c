//#Object:undefined-weak-and-strong1.c
//#LinkerDriver:clang
//#ExpectError:foo

void __attribute__((weak)) foo(void);
void call_foo(void);
int main() {
  if (foo) foo();
  call_foo();
  return 42;
}
