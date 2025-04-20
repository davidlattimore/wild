SECTIONS {
    bar : ALIGN(8) {
        start_bar = .;
        KEEP(*(.data.foo .data.baz*));
        end_bar = .;
    }
}
