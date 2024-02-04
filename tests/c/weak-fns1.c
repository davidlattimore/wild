int return_8(void) {
    return 8;
}

#if (VARIANT & 16) == 0
#if (VARIANT & 8) != 0
int __attribute__ ((weak)) weak_fn1(void) {
    return 64;
}
int __attribute__ ((weak)) weak_fn4(void) {
    return 4;
}
int __attribute__ ((weak)) weak_fn3(void) {
    return 2;
}
#else
int weak_fn1(void) {
    return  64;
};
int weak_fn4(void) {
    return 4;
}
int weak_fn3(void) {
    return return_8();
}
#endif
#endif

int strong_fn1(void) {
    return 128;
}
int strong_fn2(void) {
    return 0;
}
