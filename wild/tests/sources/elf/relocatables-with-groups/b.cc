inline int foo() { return 21; }

extern "C" int use_b() { return foo(); }
