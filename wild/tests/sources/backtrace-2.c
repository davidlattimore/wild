int bar(void);
int check_backtrace(void);

int foo(void) { bar(); }

int baz(void) { return check_backtrace(); }
