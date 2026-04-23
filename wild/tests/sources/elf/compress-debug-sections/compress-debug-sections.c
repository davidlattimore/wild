//#AbstractConfig:default
//#LinkerDriver:gcc
//#CompArgs:-g
//#LinkArgs:-Wl,--compress-debug-sections=zstd
//#SkipLinker:ld
//#SkipLinker:lld
//#DiffEnabled:false
//#ExpectCompressedSection:.debug_info
//#ExpectCompressedSection:.debug_str
//#ExpectCompressedSection:.debug_line

//#Config:gcc:default

//#Config:clang:default
//#Compiler:clang

// Tiny C program with enough code + string literals that the
// compiler emits non-trivial .debug_info / .debug_str / .debug_line
// sections — each big enough to pass the MIN_COMPRESSIBLE=256
// threshold in elf_compress.rs. The message strings are irrelevant;
// we only care that DWARF emits for them.

#include <stdio.h>

static const char *messages[] = {
    "hello from a wild-compressed debug fixture number one",
    "this is a deliberately long string to pad .debug_str",
    "third line to ensure the string table is meaningfully sized",
    "fourth and final entry, all of this is repeated often enough",
};

static int sum_lengths(void) {
    int total = 0;
    for (int i = 0; i < 4; i++) {
        const char *s = messages[i];
        while (*s) {
            total += (int)*s++;
        }
    }
    return total;
}

int main(void) {
    int a = sum_lengths();
    int b = 42;
    return (a + b) & 0;
}
