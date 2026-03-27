SECTIONS
{
    .text : { *(.text*) }
    .data.aligned : ALIGN(2048) { KEEP(*(.data.aligned)) }
    .data : { *(.data*) }
    .bss  : { *(.bss*)  }
}

ASSERT(ALIGNOF(.data.aligned) == 2048, "expected .data.aligned alignment to be 2048");
