ENTRY(begin_here)

SECTIONS
{
    . = 0x600000;
    .text : {
        *(.text)
    }
    .symbol_lookup : {
        KEEP(*(.symbol_lookup))
    }
	. += ASSERT(displaced_symbol == ADDR(.symbol_lookup) + 32, "wrong address");
    .data : {
        *(.data)
    }
    .bss : {
        KEEP(*(.bss))
    }
}

ASSERT(displaced_symbol == ADDR(.symbol_lookup) + 32, "wrong address");
