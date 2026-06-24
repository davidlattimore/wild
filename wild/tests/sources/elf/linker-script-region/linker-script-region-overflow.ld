MEMORY {
    RAM : ORIGIN = 0x10000000, LENGTH = 0x100000
    ROM : ORIGIN = 0x20000000, LENGTH = 0x100000
    FLASH : ORIGIN = 0x40000000, LENGTH = 0x3
}

SECTIONS {
    .data.flash : {
        KEEP(*(.data.flash))
    } > FLASH

    .data.ram1 : {
        KEEP(*(.data.ram1))
    } > RAM

    .data.ram2 : {
        KEEP(*(.data.ram2))
    } > RAM

    .data.rom : {
        KEEP(*(.data.rom))
    } > ROM

    .data.ram3 0x10000010 : {
        KEEP(*(.data.ram3))
    } > RAM

    .note.gnu.property : {
        *(.note.gnu.property)
    } > ROM

    .text : {
        *(.text)
    } > ROM
}
