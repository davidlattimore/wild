ENTRY(begin_here)

SECTIONS
{
    . = 0x600000;
    .text.startup : {
        start_of_startup = .;
        *linker-script-filename-match-startup*.o(.text .text.*)
    }
    .text.app : {
        start_of_app = .;
        *linker-script-filename-match-app*.o(.text .text.*)
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
