//#Object:hidden-ref1.c

// Tests that hidden visibility references resolve correctly.
// hidden-ref1.c defines foo() with default visibility.
// This file references it with hidden visibility.
__attribute__((visibility("hidden"))) int foo(void);

int main() { return foo(); }
