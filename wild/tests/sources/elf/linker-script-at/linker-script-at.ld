ENTRY(main)

SECTIONS {
    .text 0x100000 : AT(0x200000) {
        *(.text .text.*)
    }

    .data ADDR(.text) + 0x100000 : AT(ADDR(.data) + 0x100000) {
        *(.data)
    }
}

ASSERT(ADDR(.text) == 0x100000, "VMA of .text should be 0x100000");
ASSERT(ADDR(.data) == 0x200000, "VMA of .data should be 0x200000");
ASSERT(LOADADDR(.text) == 0x200000, "LMA of .text should be 0x200000");
ASSERT(LOADADDR(.data) == 0x300000, "LMA of .data should be 0x300000");
