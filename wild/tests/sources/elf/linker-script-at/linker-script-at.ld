ENTRY(main)

SECTIONS {
    .text 0x100000 : AT(0x200000) {
        *(.text .text.*)
    }

    .data ADDR(.text) + 0x100000 : AT(ADDR(.data) + 0x100000) {
        *(.data)
    }

    .empty : AT(0x400000) ALIGN(4096) {
        empty_start = .;
    }
}

ASSERT(ADDR(.text) == 0x100000, "VMA of .text should be 0x100000");
ASSERT(ADDR(.data) == 0x200000, "VMA of .data should be 0x200000");
ASSERT(LOADADDR(.text) == 0x200000, "LMA of .text should be 0x200000");
ASSERT(LOADADDR(.data) == 0x300000, "LMA of .data should be 0x300000");
ASSERT(ADDR(.empty) % 0x1000 == 0, "VMA of .empty should be aligned");
ASSERT(empty_start == ADDR(.empty), "empty_start should be the VMA of .empty");
ASSERT(LOADADDR(.empty) == 0x400000, "LMA of .empty should be 0x400000");
