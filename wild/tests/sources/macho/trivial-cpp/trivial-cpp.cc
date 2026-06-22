//#LinkerDriver:clang++
//#DiffIgnore:section.__unwind_info
//#DiffIgnore:section.__gcc_except_tab

#include <iostream>

struct Foo {
  static int foo() { return 42; }
};

int main() {
  std::cout << "hello world\n" << std::endl;
  return Foo::foo();
}
