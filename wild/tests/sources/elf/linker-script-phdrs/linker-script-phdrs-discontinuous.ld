PHDRS {
    phdr PT_PHDR PHDRS;
    text PT_LOAD FILEHDR PHDRS;
    data PT_LOAD FLAGS(6);   /* R + W */
    rodata PT_LOAD FILEHDR FLAGS(4); /* R */
}

SECTIONS {
    . = SIZEOF_HEADERS;

    .text : {
        *(.text*)
    } :text

    .data : {
        *(.data*)
    } :data

    .rodata : {
        *(.rodata*)
    } :rodata
}
