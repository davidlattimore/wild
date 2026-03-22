//#Shared:symver-shared-2.c

__asm__(".symver foo_v1,foo@VER_1.0");

int foo_v1(void);

int call_foo_v1(void) { return foo_v1(); }
