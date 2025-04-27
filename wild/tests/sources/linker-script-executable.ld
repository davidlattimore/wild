SECTIONS
{
    . = 0x600000;
    .text : {
        start_of_text = .;
        *(.text)
    }
    . = 0x800000;
    .data : {
        start_of_data = .;
        *(.data)
    }
    .bss : { *(.bss) }
}
