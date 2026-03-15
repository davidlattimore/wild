SECTIONS {
    .text : { *(.text*) }
    .data : { *(.data*) }
    .bss  : { *(.bss*)  }
}

/* A trivially true assertion - should always pass */
ASSERT(1 == 1, "1 == 1 must always be true");

/* Arithmetic assertion */
ASSERT(1 + 1 == 2, "arithmetic must work");

/* SIZEOF of a known section - just check it is >= 0 (always true for u64) */
ASSERT(SIZEOF(.text) >= 0, "text section size must be non-negative");

/* Realistic check: full evaluator path - function -> arithmetic -> comparison */
ASSERT(SIZEOF(.text) + SIZEOF(.data) < 0x100000, "image too big");
