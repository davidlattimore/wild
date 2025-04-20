SECTIONS {
    bar : ALIGN(8) {
        start_bar = .;
        KEEP(*(.data.foo .data.baz*));
        start_aaa = .;
        KEEP(*(.data.aaa));
        end_bar = .;
    }
}
