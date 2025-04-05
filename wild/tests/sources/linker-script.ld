SECTIONS {
    bar : ALIGN(8) {
        KEEP(*(.data.foo .data.baz*));
    }
}
