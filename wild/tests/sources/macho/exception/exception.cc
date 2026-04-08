//#LinkerDriver:clang++
//#LinkArgs:-lc++
//#CompArgs:-std=c++17

#include <stdexcept>

int main() {
  try {
    throw std::runtime_error("test");
  } catch (const std::runtime_error& e) {
    return 42;
  }
  return 1;
}
