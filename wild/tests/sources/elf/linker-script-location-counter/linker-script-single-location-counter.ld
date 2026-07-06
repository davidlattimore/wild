ENTRY(begin_here)

SECTIONS
{
    .text 0x600000 : {
        *(.text)
    }
    . = 0x800000;
    .data : {
        *(.data)
    }
    .bss : {
        KEEP(*(.bss))
    }
}

ASSERT(ADDR(.data) == 0x800000, "ADDR(.data) should be moved by the location counter");
