PHDRS {
    text PT_LOAD;
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
