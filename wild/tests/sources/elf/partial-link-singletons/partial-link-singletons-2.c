int repeated_data __attribute__((section("unique_referenced_data"))) = 42;
int unique_data __attribute__((section("unique_data_section"))) = 17;

__asm__(
    ".section unique_bss_section,\"aw\",@nobits\n"
    ".globl unique_bss\n"
    "unique_bss:\n"
    ".zero 4\n");
