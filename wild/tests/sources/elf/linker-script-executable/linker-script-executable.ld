ENTRY(begin_here)

SECTIONS
{
    . = 0x600000;
    .text : {
        start_of_text = .;
        *(.text)
    }
    . = 0x800000;
    . = ALIGN(4);
    .data : {
        start_of_data = .;
        *(.data)
        . = ALIGN(512);
        start_of_512 = .;
        *(.data.2)
    }
    .bss : { *(.bss) }
}
