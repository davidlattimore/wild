//#Config:dup
//#SkipLinker:ld
//#Object:duplicate_strong_symbols2.c
//#ExpectError:Duplicate symbols

int test_func(void) {
    return 0;
}

void _start(void) {
    test_func();
}
