PROVIDE(provided_absolute = 0x1000);
PROVIDE_HIDDEN(provided_hidden_absolute = 0x2000);
PROVIDE(unreferenced_sym = 0x4000);

SECTIONS {
    .text : {
        PROVIDE(__text_start = .);
        *(.text .text.*)
        PROVIDE(__text_end = .);
    }
    .data : {
        PROVIDE(__data_start = .);
        *(.data .data.*)
        PROVIDE(__data_end = .);
    }
}
