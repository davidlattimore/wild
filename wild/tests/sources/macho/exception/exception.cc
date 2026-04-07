//#LinkerDriver:clang++
//#LinkArgs:-lc++
//#CompArgs:-std=c++17
//#Ignore:__eh_frame needs FDE filtering and C++ needs __compact_unwind support

#include <stdexcept>

int main() {
  try {
    throw std::runtime_error("test");
  } catch (const std::runtime_error& e) {
    return 42;
  }
  return 1;
}
