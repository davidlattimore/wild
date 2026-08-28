ENTRY(begin_here)

SECTIONS
{
    . = 0x600000;

    .custom : {
        *(.custom.1)
        *(.custom.2)
        . = custom_two + abs_small + 0x100;
        mixed_symbol_location = .;
        *(.custom.3)
    }

    .text : {
        *(.text)
        *(.text.*)
    }

    .data : {
        *(.data)
        *(.data.*)
    }

    .bss : {
        *(.bss)
        *(.bss.*)
    }
}

ASSERT(mixed_symbol_location == custom_two + abs_small + 0x100,
       "mixed symbol expression produced the wrong address");
