// Test that linker-defined symbols with PROVIDE semantics don't conflict with user-defined symbols
//#Object:runtime.c
//#ExpectSym:_end
//#ExpectSym:__init_array_start
//#ExpectSym:__init_array_end
//#SkipLinker:ld

//#AbstractConfig:base
//#Config:1:base
//#Variant:1
// Variant 1: Reference __rela_iplt_start, expect it to be provided and hidden
//#CompArgs:-fPIC
//#LinkArgs:-shared
//#ExpectSym:__rela_iplt_start
//#ExpectSym:__rela_iplt_end
//#NoDynSym:__rela_iplt_start
//#NoDynSym:__rela_iplt_end

//#Config:2:base
//#Variant:2
// Variant 2: Define __rela_iplt_start strongly, expect it to override
//#CompArgs:-fPIC
//#LinkArgs:-shared
//#ExpectSym:__rela_iplt_start
//#ExpectSym:__rela_iplt_end
//#ExpectDynSym:__rela_iplt_start
//#ExpectDynSym:__rela_iplt_end

#include "runtime.h"

// User defines _end - linker should not create a conflicting symbol
char _end __attribute__((weak)) = 42;

// These are linker-defined symbols that should still be created
extern char __init_array_start __attribute__((weak));
extern char __init_array_end __attribute__((weak));
extern char __executable_start __attribute__((weak));

// Variant 1: Reference linker provided symbols, but don't define.
// Linker should provide them and hide them.
#if defined(VARIANT) && VARIANT == 1
extern char __rela_iplt_start[];
extern char __rela_iplt_end[];
#endif

// Variant 2: Define symbols strongly. Linker definitions should be overridden.
// Symbols should be exported if we don't hide them.
#if defined(VARIANT) && VARIANT == 2
char __rela_iplt_start[1] = {0};
char __rela_iplt_end[1] = {0};
#endif

// Variant 3: Reference __executable_start. Linker should provide and hide.
#if defined(VARIANT) && VARIANT == 3
extern char __executable_start[];
#endif

// Variant 4: Define __executable_start strongly. Should override.
#if defined(VARIANT) && VARIANT == 4
char __executable_start[10];
#endif

void _start(void) {
    runtime_init();

    // Default variant / Variant 0 checks
#if !defined(VARIANT) || VARIANT == 0
    // Just take addresses to ensure symbols are referenced
    volatile long addr = (long)&_end + (long)&__init_array_start + (long)&__init_array_end;
    
    // Check that _end address is non-zero (it should be our variable)
    if (&_end == 0) {
        exit_syscall(1);
    }
#endif

#if defined(VARIANT) && (VARIANT == 1 || VARIANT == 2)
    // Reference the symbols to ensure they are pulled in/kept
    volatile long v = (long)__rela_iplt_start + (long)__rela_iplt_end;
    (void)v;
#endif

#if defined(VARIANT) && (VARIANT == 3 || VARIANT == 4)
    // Reference __executable_start
    volatile long v = (long)__executable_start;
    (void)v;
#endif

    exit_syscall(42);
}
