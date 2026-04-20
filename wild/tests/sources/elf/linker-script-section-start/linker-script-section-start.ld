ENTRY(begin_here)

SECTIONS
{
    . = 0x600000;
    .text : { *(.text .text.*) }
    .foo 0x1000000 : { KEEP(*(.foo)) }
    .data : { *(.data .data.*) }
    .bss : { *(.bss .bss.*) }
}
