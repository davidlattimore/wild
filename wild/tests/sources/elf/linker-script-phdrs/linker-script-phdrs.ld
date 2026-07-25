PHDRS {
    text PT_LOAD;
    dynamic PT_DYNAMIC;
    empty PT_LOAD;
    data PT_LOAD FLAGS(6);   /* R + W */
    rodata PT_LOAD FLAGS(4); /* R */
}

SECTIONS {
    . = SIZEOF_HEADERS;
    start_of_sections = .;
    .text : {
        *(.text*)
    } :text

    .data : {
        *(.data*)
    } :data

    .bss : {
        *(.bss*)
    }

    .custom : {
        *(.custom)
    } :NONE

    .dynamic : {
        *(.dynamic)
    } :rodata :dynamic

    .rodata : {
        *(.rodata*)
    } :rodata :NONE
}

ASSERT(start_of_sections == 0x40 + ((5 + is_riscv) * 0x38), "Wrong start of sections");
ASSERT(SIZEOF_HEADERS == 0x40 + ((5 + is_riscv) * 0x38), "Wrong size of headers");
