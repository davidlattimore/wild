__asm__(".symver foo_impl,foo@VER_1.0");

int foo_impl(void) { return 42; }
