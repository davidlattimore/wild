//#LinkerDriver:clang++
//#ExpectSection:__init_offsets
//#NoSection:__mod_init_func
//#DiffIgnore:section.__unwind_info
//#DiffIgnore:section.__gcc_except_tab

#include <iostream>

int v = 0;

namespace {

class Tracer {
 public:
  Tracer() {
    v = 42;
    std::cout << "new\n";
  }
  ~Tracer() { std::cout << "destroy\n"; }
};

}  // namespace

Tracer globalA;

Tracer& functionStatic() {
  static Tracer object{};
  return object;
}

int main() { return v; }
