//#LinkerDriver:clang++
//#ExpectWarningWild:Fat object file is not supported yet

#include <iostream>

struct Foo {
  static int foo() { return 42; }
};

int main() {
  std::cout << "hello world\n" << std::endl;
  return Foo::foo();
}
