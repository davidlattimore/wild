PROVIDE(provided_absolute = 0x1000);
PROVIDE_HIDDEN(provided_hidden_absolute = 0x2000);
PROVIDE(provided_symbol = provided_absolute);
PROVIDE(provided_expr1 = provided_symbol + provided_hidden_absolute);
PROVIDE(provided_expr2 = (0xffffffff80000000 + (((provided_absolute * 0x1000) + (provided_hidden_absolute * 0x100 - 1)) & ~(0x200000 - 1))));
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
