SECTIONS {
    bar : ALIGN(8) {
        start_bar = .;
        KEEP(*(.data.foo .data.baz*));
        start_aaa = .;
        KEEP(*(.data.aaa));
        end_bar = .;
    }
}
defsym_start_aaa = start_aaa;
defsym_addr = 0x1234;
