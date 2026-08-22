ENTRY(begin_here)

SECTIONS
{
    . = 0x600000;
    .text : {
        *(.text)
    }
	text_end = .;

    . += 0x40;

    .data : {
        *(.data)
        *(.data.*)
    }

    . = . + 0x40;

    .bss : {
        KEEP(*(.bss))
    }
}

ASSERT(ADDR(.text.foo) >= ADDR(.text) + SIZEOF(.text), ".text.foo should be placed after .text");
ASSERT(ADDR(.text.foo) < ADDR(.data), ".data should be placed after .text.foo");
ASSERT(text_end == ADDR(.text) + SIZEOF(.text), "text_end is incorrect");
