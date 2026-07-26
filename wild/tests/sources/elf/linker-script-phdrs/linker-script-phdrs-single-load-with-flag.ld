PHDRS {
    text PT_LOAD FLAGS(5);
}

SECTIONS {
    .text : {
        *(.text*)
    } :text

    .data : {
        *(.data*)
    }

    .bss : {
        *(.bss*)
    }

    .rodata : {
        *(.rodata*)
    }
}
