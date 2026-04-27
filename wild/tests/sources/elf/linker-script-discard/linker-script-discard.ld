SECTIONS {
    keep : {
        KEEP(*(.data.keep))
    }

    /DISCARD/ : {
        *(.data.drop)
    }
}
