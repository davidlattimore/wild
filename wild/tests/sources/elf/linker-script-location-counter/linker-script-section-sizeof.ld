ENTRY(begin_here)

SECTIONS
{
    . = 0x600000;
    .text : {
        *(.text)
    }
    . = 0x800000;
    .foo : {
        KEEP(*(.foo.first))
        KEEP(*(.foo.second))
    }
}

ASSERT(SIZEOF(.foo) == 12, "foo section size must be 12");
