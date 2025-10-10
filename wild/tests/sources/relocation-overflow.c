//#Config:default
//#Object:relocation-overflow-b.c
//#SkipLinker:ld
//#Mode:dynamic
//#Arch:x86_64
//#ExpectError:Failed to apply relocation of type R_X86_64_PC32

char big_a[0x90000000];

// Force a 32-bit relocation overflow
asm(".section .data\n"
    ".global reloc_a_to_b\n"
    "reloc_a_to_b:\n"
    "    .long big_b - .\n"  //  R_X86_64_PC32 relocation
    ".text\n");

extern int reloc_a_to_b;
void *keep_a_ref(void) { return &reloc_a_to_b; }
extern void *keep_b_ref(void);

void _start() {
  keep_a_ref();
  keep_b_ref();
}
