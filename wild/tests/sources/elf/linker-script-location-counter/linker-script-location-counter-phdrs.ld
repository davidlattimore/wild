ENTRY(begin_here)

PHDRS {
    text PT_LOAD;
    data PT_LOAD FLAGS(6);
    rodata PT_LOAD FLAGS(4);
}

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
        . = 0x200;
        text_foo_sym = .;
        *(.text.foo)
        . = 0x1000;
        text2 = .;
    } :text
    . = 0x3fffff;
    . = . * 2;
    start_of_unaligned_data = .;
    . = ALIGN(8);
    start_of_data = .;
    .data : {
        *(.data)
    } :data

    .bss : {
        KEEP(*(.bss))
    } :data

    .eh_frame : {
        KEEP(*(.eh_frame))
    } :rodata
}

ASSERT(start_of_sections == 0x600000, "start_of_sections should be 0x600000");
ASSERT(start_of_unaligned_data == 0x7ffffe, "start_of_unaligned_data should be 0x7ffffe");
ASSERT(start_of_data == 0x800000, "start_of_data should be 0x800000");
ASSERT(SIZEOF(.text) == 0x1000, "text section should be 0x1000 bytes");
ASSERT(text1 == start_of_text + 0x10, "text1 should be 0x10 bytes after start_of_sections");
ASSERT(text_foo_sym == start_of_text + 0x200, "text_foo_sym should be 0x200");
ASSERT(text2 == start_of_text + 0x1000, "text2 should be 0x1000 bytes after start_of_sections");
ASSERT(ADDR(.data) == 0x800000, "ADDR(.data) should be 0x800000");
ASSERT(ADDR(.bss) == ADDR(.data) + SIZEOF(.data), "ADDR(.bss) should be ADDR(.data) + SIZEOF(.data)");
