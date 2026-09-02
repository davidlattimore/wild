ENTRY(begin_here)

first = second;
second = first;

SECTIONS
{
    . = first;
    .text : {
        *(.text)
    }
    .data : {
        *(.data)
    }
    .bss : {
        KEEP(*(.bss))
    }
}
