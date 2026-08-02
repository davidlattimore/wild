__attribute__((used, section(".text.sort.b"))) int func_b() { return 2; }

__attribute__((used, aligned(16), section(".text.align.16"))) int align_16() { return 16; }
__attribute__((used, aligned(64), section(".text.align.64"))) int align_64() { return 64; }
__attribute__((used, aligned(4), section(".text.align.4"))) int align_4() { return 4; }
__attribute__((used, aligned(32), section(".text.align.32"))) int align_32() { return 32; }

__attribute__((section(".text.kept.func"))) int func_kept() { return 4; }
__attribute__((section(".text.drop.func"))) int func_drop() { return 5; }
