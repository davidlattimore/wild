//#CompArgs:freestanding:-ffreestanding -fno-builtin
//#InputType: Object

#include "exit.h"

#if (VARIANT & 1) != 0
int weak_var1 __attribute__ ((weak)) = 2; // 64
int weak_var2 __attribute__ ((weak)) = 8;
int weak_var3 __attribute__ ((weak)) = 0; // 2
int weak_arr1[4] __attribute__ ((weak)) = {1, 1, 1, 1}; // 4
int weak_arr2[4] __attribute__ ((weak)) = {16, 16, 16, 16};
#else
extern int weak_var1 __attribute__ ((weak));
extern int weak_var2 __attribute__ ((weak));
extern int weak_var3 __attribute__ ((weak));
extern int weak_arr1[4] __attribute__ ((weak));
extern int weak_arr2[4] __attribute__ ((weak));
#endif

extern int strong_var1;
extern int strong_var2;

void _start() {
    int value = 0;
    if (&weak_var1) {
        value += weak_var1;
    }
    if (&weak_var2) {
        value += weak_var2;
    }
    if (&weak_var3) {
        // This is different in that it doesn't reference the weak variable in the block, which
        // means it optimises differently.
        value += 32;
    }
    if (weak_arr1) {
        value += weak_arr1[2];
    }
    if (weak_arr2) {
        value += weak_arr2[2];
    }

    // Referencing a strong variable that's defined in the same object as our weak symbols can
    // affect what definition gets used. We have two strong variables, one in DATA, the same as our
    // weak variables, the other in BSS. We only ever want one or the other, but we also want to try
    // neither, so we use a bit for each.
#if (VARIANT & 2) != 0
    value += strong_var1;
#endif
#if (VARIANT & 4) != 0
    value += strong_var2;
#endif

    // Variant bits:
    // 1:  Weak variables in this file also have definitions
    // 2:  Reference to strong var in DATA in other file
    // 4:  Reference to strong var in BSS in other file
    // 8:  Variables weakly defined in other file
    // 16: Variables undefined in second file

    int expected[24] = {
        //#Variant: 0
        // Variables defined strongly in second file, no strong refs
        64 + 32 + 4,
        //#Variant: 1
        // Variables defined weakly here then strongly in second, no strong refs
        64 + 8 + 32 + 4 + 16,
        //#Variant: 2
        // Variables defined weakly here then strongly in second, strong ref to DATA
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
        //#Variant: 8
        // Variables defined weakly in second file, no strong refs
        64 + 32 + 4,
        //#Variant: 9
        // Variables defined weakly here and in second file, no strong refs
        2 + 8 + 32 + 1 + 16,
        //#Variant: 10
        // Variables defined weakly in second file, strong ref to DATA
        64 + 32 + 4 + 128,
        // 11
        0,
        //#Variant: 12
        // Variables defined weakly here and in second file, strong ref to BSS
        64 + 32 + 4,
        // 13
        0,
        // 14
        0,
        // 15
        0,
        //#Variant: 16
        // No weak variables defined in either file
        0,
        //#Variant: 17
        // Variables weakly defined in this file only.
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
        0,
        // 24
    };

    if (value == 42) {
        value = 127;
    } else if (value == expected[VARIANT]) {
        value = 42;
    }

    exit_syscall(value);
}
