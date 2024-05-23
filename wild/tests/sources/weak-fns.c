//#AbstractConfig:default
//#Object:weak-fns1.c
//#Object:exit.c
//#CompArgs:-fno-stack-protector

#include "exit.h"

#if (VARIANT & 1) != 0
int __attribute__ ((weak)) weak_fn1(void) {
    return 2;  // 64
}
int __attribute__ ((weak)) weak_fn2(void) {
    return 8;
}
int __attribute__ ((weak)) weak_fn3(void) {
    return 0; // 2
}
int __attribute__ ((weak)) weak_fn4(void) {
    return 1; // 4
}
int __attribute__ ((weak)) weak_fn5(void) {
    return 16;
}
#else
int __attribute__ ((weak)) weak_fn1(void);
int __attribute__ ((weak)) weak_fn2(void);
int __attribute__ ((weak)) weak_fn3(void);
int __attribute__ ((weak)) weak_fn4(void);
int __attribute__ ((weak)) weak_fn5(void);
#endif

int strong_fn1();
int strong_fn2();

void _start() {
    int value = 0;
    if (&weak_fn1) {
        value += weak_fn1();
    }
    if (&weak_fn2) {
        value += weak_fn2();
    }
    if (&weak_fn3) {
        // This is different in that it doesn't reference the weak variable in the block, which
        // means it optimises differently.
        value += 32;
    }
    if (weak_fn4) {
        value += weak_fn4();
    }
    if (weak_fn5) {
        value += weak_fn5();
    }

#if (VARIANT & 2) != 0
    value += strong_fn1();
#endif
#if (VARIANT & 4) != 0
    value += strong_fn2();
#endif

    // Variant bits:
    // 1:  Weak Functions in this file also have definitions
    // 2:  Reference to strong fn in other file
    // 4:  Reference to strong fn in other file
    // 8:  Functions weakly defined in other file
    // 16: Functions undefined in second file

    int expected[24] = {
        //#Config:0:default
        //#Variant: 0
        // Functions defined strongly in second file, no strong refs
        64 + 32 + 4,
        //#Config:1:default
        //#Variant: 1
        // Functions defined weakly here then strongly in second, no strong refs
        64 + 8 + 32 + 4 + 16,
        //#Config:2:default
        //#Variant: 2
        // Functions defined weakly here then strongly in second, strong ref
        64 + 32 + 4 + 128,
        // 3
        0,
        // 4
        0,
        // 5
        0,
        // 6
        0,
        // 7
        0,
        //#Config:8:default
        //#Variant: 8
        // Functions defined weakly in second file, no strong refs
        64 + 32 + 4,
        //#Config:9:default
        //#Variant: 9
        // Functions defined weakly here and in second file, no strong refs
        2 + 8 + 32 + 1 + 16,
        //#Config:10:default
        //#Variant: 10
        // Functions defined weakly in second file, strong ref
        64 + 32 + 4 + 128,
        // 11
        0,
        //#Config:12:default
        //#Variant: 12
        // Functions defined weakly here and in second file, strong ref
        64 + 32 + 4,
        // 13
        0,
        // 14
        0,
        // 15
        0,
        //#Config:16:default
        //#Variant: 16
        // No weak functions defined in either file
        0,
        //#Config:17:default
        //#Variant: 17
        // Functions weakly defined in this file only.
        2 + 8 + 32 + 1 + 16,
        // 18
        0,
        // 19
        0,
        // 20
        0,
        // 21
        0,
        // 22
        0,
        // 23
        0
    };

    if (value == 42) {
        value = 127;
    } else if (value == expected[VARIANT]) {
        value = 42;
    }

    exit_syscall(value);
}
