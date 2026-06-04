__attribute__((used, section(".text.sort.b"))) int func_b() { return 2; }

__attribute__((section(".text.kept.func"))) int func_kept() { return 4; }
__attribute__((section(".text.drop.func"))) int func_drop() { return 5; }
