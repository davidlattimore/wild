PHDRS {
    text PT_DYNAMIC;
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
