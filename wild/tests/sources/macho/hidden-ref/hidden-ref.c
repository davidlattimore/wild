//#Object:hidden-ref1.c
//#Object:hidden-ref2.c
//#Ignore:dylib creation needed to test hidden symbol visibility

// Tests that a hidden symbol is not exported from a dylib.
// hidden-ref1.c defines foo() as default visibility.
// hidden-ref2.c defines foo() as hidden.
// When linked into a dylib, hidden should win and foo should not be exported.

__attribute__((visibility(("hidden")))) int foo(void);

int main() { return foo(); }
