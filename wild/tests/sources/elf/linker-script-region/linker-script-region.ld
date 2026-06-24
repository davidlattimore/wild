MEMORY {
    RAM : ORIGIN = 0x10000000, LENGTH = 0x100000
    ROM : ORIGIN = 0x20000000, LENGTH = 0x100000
    FLASH : ORIGIN = 0x40000000, LENGTH = 0x4
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

ASSERT(ORIGIN(RAM) + LENGTH(RAM) == 0x10100000, "RAM region overflowed")
ASSERT(ORIGIN(ROM) + LENGTH(ROM) == 0x20100000, "ROM region overflowed")

ASSERT(ADDR(.data.ram1) == 0x10000000, "data.ram1 address is wrong")
ASSERT(ADDR(.data.ram2) == 0x10000004, "data.ram2 address is wrong")
ASSERT(ADDR(.data.ram3) == 0x10000010, "data.ram3 address is wrong")
/* Some linkers don't emit .note.gnu.property, so .data.rom may not start at 0x20000000 */
ASSERT(ADDR(.data.rom) >= 0x20000000, "data.rom address is wrong")

ASSERT(SIZEOF(.data.flash) == 0x4, "data.flash size is wrong")
