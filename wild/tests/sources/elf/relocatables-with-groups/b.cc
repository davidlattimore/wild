inline int foo() { return 7; }

extern "C" int use_b() { return foo(); }
