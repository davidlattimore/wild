int baz(void);

int call_baz(void) {
    return baz();
}

int bar2(void) {
    return 2;
}

__attribute__((weak)) int foo1 = 3;
__attribute__((weak)) int get_foo() { return 4; }
