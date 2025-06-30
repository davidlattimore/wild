//#Shared:shlib-undefined-3.c

int def1(void);
int def2(void);

int call_def1(void) {
    return def1();
}

int call_def2(void) {
    return def2();
}
