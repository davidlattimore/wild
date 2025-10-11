char big_b[0x90000000];

asm(".section .data\n"
    ".global reloc_b_to_a\n"
    "reloc_b_to_a:\n"
    "    .long big_a - .\n"  // R_X86_64_PC32 relocation
    ".text\n");

extern int reloc_b_to_a;
void* keep_b_ref(void) { return &reloc_b_to_a; }
