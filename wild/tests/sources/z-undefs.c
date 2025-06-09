//#LinkArgs:-Bshareable -z undefs -z now
//#Static:false

int foo(void);

int call_foo(void) { return foo() + 2; }
