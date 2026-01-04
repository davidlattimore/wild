int get_11(void);

__asm__(".symver foo_impl,foo@VER_1.0");
__asm__(".symver bar_impl,bar@VER_1.0");

int foo_impl(void) { return 10; }
int bar_impl(void) { return get_11(); }
