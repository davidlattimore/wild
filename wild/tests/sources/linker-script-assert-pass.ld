ENTRY(_start)

SECTIONS {
    .text : { *(.text*) }
    .data : { *(.data*) }
    .bss  : { *(.bss*)  }
}

/* A trivially true assertion - should always pass */
ASSERT(1 == 1, "1 == 1 must always be true");

/* Arithmetic assertion */
ASSERT(1 + 1 == 2, "arithmetic must work");

/* SIZEOF(.text) should be > 0 since _start is in it */
ASSERT(SIZEOF(.text) > 0, "text section must be non-empty");

/* Realistic check: full evaluator path - function -> arithmetic -> comparison */
ASSERT(SIZEOF(.text) + SIZEOF(.data) < 0x100000, "image too big");
