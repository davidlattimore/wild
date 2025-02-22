//#AbstractConfig:default
//#Object:exit.c

//#Config:archive:default
//#Archive:custom_section0.c

//#Config:object:default
//#Object:custom_section0.c

#include "exit.h"

static int foo1 __attribute__ ((used, section ("foo"))) = 2;
static int foo2 __attribute__ ((used, section ("foo"))) = 5;

static int w1a __attribute__ ((used, section ("w1"))) = 88;
static int w3a __attribute__ ((used, section ("w3"))) = 88;

extern int __start_foo[];
extern int __stop_foo[];

// The `bar` section is only defined in our other file.
extern int __start_bar[];
extern int __stop_bar[];

extern int __start_w1[] __attribute__ ((weak));
extern int __stop_w1[] __attribute__ ((weak));
extern int __start_w2[] __attribute__ ((weak));
extern int __stop_w2[] __attribute__ ((weak));

static int dot1 __attribute__ ((used, section (".dot"))) = 7;
static int dot2 __attribute__ ((used, section (".dot.2"))) = 8;

// Make sure we don't discard this custom, alloc section just because of its name.
static int debug_script __attribute__ ((section (".debug_script"))) = 15;

// Override a symbol that would normally be created by the custom section.
int __stop_w3 = 88;

// Not really custom-section related, but also override a symbol that's normally defined by a
// built-in section.
int __init_array_start = 89;

int fn1(void);
void set_foo1(int value);
int get_foo1(void);
int h1();
int h2(int x);

void _start(void) {
    int value = fn1();
    for (int *foo = __start_foo; foo < __stop_foo; foo++) {
        value += *foo;
    }
    for (int *bar = __start_bar; bar < __stop_bar; bar++) {
        value += *bar;
    }
    if (__start_w2 || __stop_w2) {
        exit_syscall(100);
    }
    if (__start_w1 == __stop_w1) {
        exit_syscall(101);
    }
    if (__start_w1[0] != 88) {
        exit_syscall(102);
    }
    if (h1() != 6) {
        exit_syscall(103);
    }
    if (h2(2) != 8) {
        exit_syscall(104);
    }
    if (__stop_w3 != 88) {
        exit_syscall(105);
    }
    if (__init_array_start != 89) {
        exit_syscall(106);
    }
    if (dot1 != 7) {
        exit_syscall(107);
    }
    if (dot2 != 8) {
        exit_syscall(108);
    }
    // Verify that we can write to a custom section.
    set_foo1(10);
    if (get_foo1() != 10) {
        exit_syscall(109);
    }

    if (debug_script != 15) {
        exit_syscall(110);
    }

    exit_syscall(value);
}

//#ExpectSym: dot1 .dot
//#ExpectSym: dot2 .dot.2
