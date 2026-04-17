SECTIONS
{
    .foo 0x1000000 : { *(.foo) }
    .text : { *(.text) }
    .rodata : { *(.rodata*) }
    .data : { *(.data) }
    .bss : { *(.bss) }
}
