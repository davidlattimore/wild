ENTRY(_start)

SECTIONS {
    .text : {
        *(.text*)
        symbol3 = 0x3000;
    }
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

symbol1 = 0x1000;
symbol2 = 0x2000;

ASSERT(symbol1 == 0x1000, "symbol1 must be 0x1000");
ASSERT(symbol1 + symbol2 == 0x3000, "symbol1 + symbol2 must be 0x3000");
ASSERT(symbol1 + symbol2 != symbol1 - symbol2, "symbol1 + symbol2 must not be symbol1 - symbol2");
ASSERT(0xffffffff81000000 == (0xffffffff80000000 + (((symbol1 * 0x1000) + (symbol2 * 0x100 - 1)) & ~(0x200000 - 1))), "Incorrect Value");
ASSERT((5 > 4 ? !1 ? 3 : 5 : 4) == 5, "5 > 4 ? !1 ? 3 : 5 : 4 must be 5");
ASSERT((symbol1 > symbol2 ? symbol1 : symbol2) == MAX(symbol1, symbol2), "Expected MAX(symbol1, symbol2)");
ASSERT(DEFINED(symbol1), "symbol1 must be defined");
ASSERT(DEFINED(symbol3), "symbol3 must be defined");
ASSERT(DEFINED(symbol4), "symbol4 must be defined");
ASSERT(!DEFINED(symbol5), "symbol5 should not be defined");
ASSERT(DEFINED(symbol6), "symbol6 must be defined");
ASSERT(DEFINED(symbol7), "symbol7 must be defined");
ASSERT(!DEFINED(symbol8), "symbol8 should not be defined");
