SECTIONS {
    .text : {
        *(.text.1)
        . = . + 0x10;
        *(.text.2)
    } =0x90909090
}
