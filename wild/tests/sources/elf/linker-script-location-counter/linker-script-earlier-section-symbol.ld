ENTRY(begin_here)

SECTIONS
{
    . = 0x10000;

    .text : {
        *(.text)
        *(.text.*)
    }

    . = 0x20000;

    .data : {
        . = foo + 0x20000;
        data_from_earlier_section = .;
        *(.data)
        *(.data.*)
    }

    .bss : {
        *(.bss)
        *(.bss.*)
    }
}

ASSERT(data_from_earlier_section == foo + 0x20000, "incorrect address from earlier section symbol");
