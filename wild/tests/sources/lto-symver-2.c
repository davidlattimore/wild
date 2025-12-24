__asm__(".symver foo_v1, foo@VER_1.0");
int foo_v1(void);

__asm__(".symver bar_v1, bar@VER_1.0");
int bar_v1(void);

int call_versioned_symbols(void) {
  if (foo_v1() != 10) {
    return 10;
  }
  if (bar_v1() != 11) {
    return 11;
  }

  return 42;
}
