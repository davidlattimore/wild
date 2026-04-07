//#LinkerDriver:clang
//#Ignore:weak undefined symbols not yet resolved to NULL for Mach-O

int __attribute__((weak)) foo(void);
int main() {
  if (foo) return foo();
  return 42;  // foo is NULL, so we take this path
}
