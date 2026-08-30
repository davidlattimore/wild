ENTRY(begin_here)

SECTIONS
{
    . = 0x600000;

    .custom : {
        *(.custom.1)
        *(.custom.2)
        . = custom_two + 0x100;
        *(.custom.3)
    }

    .sort : {
        KEEP(*(SORT_BY_NAME(.sort.*)))
    }
}

ASSERT(sort_a < sort_b && sort_b < sort_c, "sort order is incorrect");
