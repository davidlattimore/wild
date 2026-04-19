inline int foo() { return 21; }

extern "C" int use_a() { return foo(); }
