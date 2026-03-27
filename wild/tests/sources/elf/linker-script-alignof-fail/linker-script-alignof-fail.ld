SECTIONS
{
    .text : { *(.text*) }
    .data : { *(.data*) }
    .bss  : { *(.bss*)  }
}

ASSERT(ALIGNOF(.data) == 2048, "expected .data alignment to be 2048");
