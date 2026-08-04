PHDRS {
    phdr PT_PHDR PHDRS;
    text PT_LOAD FILEHDR PHDRS;
    dynamic PT_DYNAMIC FILEHDR;
    data PT_LOAD FLAGS(6);   /* R + W */
    rodata PT_LOAD FLAGS(4); /* R */
}

SECTIONS {
    . = SIZEOF_HEADERS;

    .text : {
        *(.text*)
    } :text

    .data : {
        *(.data*)
    } :data

    .dynamic : {
        *(.dynamic)
    } :dynamic

    .rodata : {
        *(.rodata*)
    } :rodata
}
