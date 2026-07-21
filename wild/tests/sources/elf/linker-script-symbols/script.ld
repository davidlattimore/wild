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
