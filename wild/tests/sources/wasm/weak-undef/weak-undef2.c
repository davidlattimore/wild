__attribute__((weak)) int optional_foo(int x);

int other_uses_foo(void) {
  if (optional_foo) {
    return optional_foo(1) == 2 ? 0 : 1;
  }
  return 0;
}
