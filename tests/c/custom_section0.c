static int foo1 __attribute__ ((used, retain, section ("foo"))) = 1;
static int foo2 __attribute__ ((used, retain, section ("foo"))) = 20;
static int foo3 __attribute__ ((used, retain, section ("foo"))) = 5;

static int bar1 __attribute__ ((used, retain, section ("bar"))) = 7;

int fn1(void) {
    return 2;
}

int __attribute__ ((section ("hot"))) h1() {
    return 6;
}

int __attribute__ ((section ("hot"))) h2(int x) {
    return 6 + x;
}
