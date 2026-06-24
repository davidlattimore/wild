MEMORY {
    RAM : ORIGIN = 0x10000000, LENGTH = 0x100000
    ROM : ORIGIN = 0x20000000, LENGTH = 0x100000
}

SECTIONS {
    .data.ram1 : {
        KEEP(*(.data.ram1))
    } > FLASH
}
