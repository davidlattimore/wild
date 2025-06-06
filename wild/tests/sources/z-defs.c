//#LinkArgs:-Bshareable -z defs -z now
//#Mode:dynamic
//#ExpectError:foo

int foo(void);

int call_foo(void) { return foo() + 2; }
