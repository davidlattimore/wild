//#LinkArgs:-Bshareable -z defs
//#Static:false
//#ExpectError:foo

int foo(void);

int call_foo(void) { return foo() + 2; }
