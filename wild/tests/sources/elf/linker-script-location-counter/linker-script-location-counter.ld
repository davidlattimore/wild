ENTRY(begin_here)

SECTIONS
{
    . = 0x300000 * 2;
    start_of_sections = .;
    .text : {
        start_of_text = .;
        . = 0x8;
        . = . * 2;
        text1 = .;
        *(.text)
        . = 0x1000;
        text2 = .;
    }
    . = 0x400000;
    . = . * 2;
    start_of_data = .;
    .data : {
        *(.data)
    }

    .bss : {
        KEEP(*(.bss))
    }
}

ASSERT(start_of_sections == 0x600000, "start_of_sections should be 0x600000");
ASSERT(start_of_data == 0x800000, "start_of_data should be 0x800000");
ASSERT(SIZEOF(.text) == 0x1000, "text section should be 0x1000 bytes");
ASSERT(text1 == start_of_text + 0x10, "text1 should be 0x10 bytes after start_of_sections");
ASSERT(text2 == start_of_text + 0x1000, "text2 should be 0x1000 bytes after start_of_sections");
ASSERT(ADDR(.data) == 0x800000, "ADDR(.data) should be 0x800000");
ASSERT(ADDR(.bss) == ADDR(.data) + SIZEOF(.data), "ADDR(.bss) should be ADDR(.data) + SIZEOF(.data)");
