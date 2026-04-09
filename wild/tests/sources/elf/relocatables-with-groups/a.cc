inline int foo() { return 21; }

inline int bar() { return 7; }

extern "C" int use_a() { return foo(); }
