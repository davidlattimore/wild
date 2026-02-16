// User defines _end - linker should not create a conflicting symbol
char _end = 42;

// These are linker-defined symbols that should still be created
extern char __init_array_start __attribute__((weak));
extern char __init_array_end __attribute__((weak));

int main(void) {
    // Reference the symbols to ensure they're not optimized away
    return _end + (long)&__init_array_start + (long)&__init_array_end;
}
