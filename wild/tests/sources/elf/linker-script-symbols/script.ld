PROVIDE(value1a = value1);
PROVIDE(value2a = value2);
PROVIDE(foo_alias = foo);

SECTIONS {
    .text : {
        *(.text)
    }

    .rodata : {
        *(.rodata)
    }

    value3 = .;
}

value4 = 0x10;
value4 = value4 + 0x20;
ASSERT(value4 == 0x30, "Value4 is incorrect")
