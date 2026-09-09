//#LinkerDriver:clang++
//#ExpectSection:__init_offsets
//#NoSection:__mod_init_func
//#DiffIgnore:section.__unwind_info
//#DiffIgnore:section.__gcc_except_tab

// The test verifies we can actually relax 2 GOT-relative relocations
// pointing to a symbol defined in this translation unit:
// ARM64_RELOC_GOT_LOAD_PAGE21, ARM64_RELOC_GOT_LOAD_PAGEOFF12

#include <iostream>

int v = 0;

class Tracer {
 public:
  Tracer() {
    v = 42;
    std::cout << "new\n";
  }
  ~Tracer() { std::cout << "destroy\n"; }
};

Tracer globalA;

Tracer& functionStatic() {
  static Tracer object{};
  return object;
}

int main() { return v; }
