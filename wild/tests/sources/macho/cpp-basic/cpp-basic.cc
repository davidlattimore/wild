//#CompArgs:-std=c++17
//#LinkerDriver:clang++
//#LinkArgs:-lc++

// Test basic C++ linking: virtual dispatch, new/delete.
struct Base {
  virtual int value() { return 1; }
  virtual ~Base() = default;
};

struct Derived : Base {
  int value() override { return 42; }
};

int main() {
  Derived d;
  Base* b = &d;
  return b->value();
}
