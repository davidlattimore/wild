ENTRY(begin_here)

SECTIONS
{
    . = 0x600000;
    .text.startup : {
        start_of_startup = .;
        *input-filename-startup*.o(.text .text.*)
    }
    .text.app : {
        start_of_app = .;
        *input-filename-app*.o(.text .text.*)
    }
    .text : {
        start_of_text = .;
        *(.text .text.*)
    }
    . = 0x800000;
    . = ALIGN(4);
    .data : { *(.data .data.*) }
    .bss : { *(.bss .bss.*) }
}
