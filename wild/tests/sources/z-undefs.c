//#LinkArgs:-Bshareable -z undefs
//#Static:false

int foo(void);

int call_foo(void) { return foo() + 2; }
