SECTIONS {
    .text : { *(.text*) }
    .data : { *(.data*) }
    .bss  : { *(.bss*)  }
}


symbol1 = 0x1000;
ASSERT(symbol1 == 0x2000, "symbol1 must be 0x2000");
