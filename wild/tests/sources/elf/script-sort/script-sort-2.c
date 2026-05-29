// wild/tests/sources/elf/script-sort/script-sort-2.c

__attribute__((used, section(".text.func_b"))) int func_b() { return 2; }

// GC test function
__attribute__((section(".text.func_kept"))) int func_kept() { return 4; }
