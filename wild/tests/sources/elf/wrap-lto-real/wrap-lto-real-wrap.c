int __real_foo(void);

int __wrap_foo(void) { return __real_foo() + 32; }
