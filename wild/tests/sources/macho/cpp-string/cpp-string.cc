//#LinkerDriver:clang++
//#LinkArgs:-lc++
//#CompArgs:-std=c++17

// Tests C++ std::string and basic stdlib linking.
#include <string>

int main() {
  std::string s = "hello";
  s += " world";
  return s.length() == 11 ? 42 : 1;
}
