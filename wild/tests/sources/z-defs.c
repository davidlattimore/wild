//#LinkArgs:-Bshareable -z defs
//#Mode:dynamic
//#ExpectError:foo

int foo(void);

int call_foo(void) { return foo() + 2; }
