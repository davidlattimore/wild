ENTRY(begin_here)

SECTIONS
{
    . = 0x600000;

    .text : {
        *(.text)
        *(.text.*)
    }

    .location_counter_target : {
        *(.location_counter_target)
        . = location_counter_only_symbol + 0x100;
        location_after_only_reference = .;
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

ASSERT(location_after_only_reference == ADDR(.location_counter_target) + 0x100,
       "location counter target was not positioned correctly");
