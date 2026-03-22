SECTIONS {
    .text : { *(.text*) }
    .data : { *(.data*) }
    .bss  : { *(.bss*)  }
}

/* This assertion is always false - linker must abort with this message */
ASSERT(0, "assertion failed: text section cannot be empty");
