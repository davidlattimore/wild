int bar = 1;

// Because this alias is a weak symbol, any copy relocations produced by references to foo should
// instead locate the strong symbol `bar` that is at the same address and emit a copy relocation for
// that instead.
__attribute__ ((weak, alias("bar"))) extern int foo;

int get_foo(void) {
    return bar;
}

// Repeat the same scenario twice more. These are effectively identical in this file. The
// differences are in how they are referenced in the main file.

int bar2 = 2;

__attribute__ ((weak, alias("bar2"))) extern int foo2;

int get_foo2(void) {
    return bar2;
}

int bar3 = 3;

__attribute__ ((weak, alias("bar3"))) extern int foo3;

int get_foo3(void) {
    return bar3;
}
