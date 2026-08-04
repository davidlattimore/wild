PHDRS {
    phdr PT_PHDR PHDRS;
    hdr PT_PHDR FILEHDR;
    text PT_LOAD FILEHDR PHDRS;
    hdr_load PT_LOAD FILEHDR PHDRS;
    dynamic PT_DYNAMIC;
    data PT_LOAD FLAGS(6) FILEHDR PHDRS;   /* R + W */
    rodata PT_LOAD FLAGS(4); /* R */
    hdr_tls PT_TLS FILEHDR PHDRS;
}

SECTIONS {
    . = SIZEOF_HEADERS;

    .text : {
        *(.text*)
    } :text

    .data : {
        *(.data*)
    } :data

    .bss : {
        *(.bss*)
    }

    .dynamic : {
        *(.dynamic)
    } :rodata :dynamic

    .rodata : {
        *(.rodata*)
    } :rodata
}
