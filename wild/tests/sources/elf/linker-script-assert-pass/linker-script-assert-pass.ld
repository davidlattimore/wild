ENTRY(_start)

SECTIONS {
    .text : {
        *(.text*)
        symbol3 = 0x3000;
    }
    symbol11 = 0x100;
    symbol11_assert = ASSERT(symbol11 == 0x100, "symbol11 must be 0x100");
    symbol11 -= 0x20;
    symbol11 &= 0x80;
    ASSERT(symbol11 == 0x80, "symbol11 must be 0x80")
    .data : AT(ADDR(.data) + 0x10000) {
        data_start = .;
        *(.data*)
        symbol10 = 0x100;
        symbol10_assert = ASSERT(symbol10 == 0x100, "symbol10 must be 0x100");
        symbol10 *= 0x100;
        symbol10 ^= 0x40;
        ASSERT(symbol10 == 0x10040, "symbol10 must be 0x10040");
        ASSERT(data_start == ADDR(.data), "data_start must be ADDR(.data)");
        ASSERT(data_start + 0x10000 == LOADADDR(.data), "data_start + 0x10000 must be LOADADDR(.data)");
    }
    .bss  : { *(.bss*)  }
}

/* A trivially true assertion - should always pass */
ASSERT(1 == 1, "1 == 1 must always be true");

/* Arithmetic assertion */
ASSERT(1 + 1 == 2, "arithmetic must work");
ASSERT(12 / 10 == 1, "pos / pos division");
ASSERT(-50 / 10 == -5, "neg / pos division failed");
ASSERT(60 / -10 == -6, "pos / neg division failed");
ASSERT(-40 / -10 == 4, "neg / neg division failed");
ASSERT(12 % 10 == 2, "pos % pos modulo failed");
ASSERT(-5 % 10 == -5, "neg % pos modulo failed");
ASSERT(13 % -10 == 3, "pos % neg modulo failed");
ASSERT(-12 % -10 == -2, "neg % neg modulo failed");

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

symbol9 = 0x8;
symbol9 += 0x10;
ASSERT(symbol9 == 0x18, "symbol9 must be 0x18");
symbol9 /= 0x2;
symbol9 <<= 0x3;
symbol9 |= 0x100;
ASSERT(symbol9 == 0x160, "symbol9 must be 0x160");

symbol12 = ASSERT(ASSERT(0x5000 < 0x10000, "0x5000 < 0x10000 must be true") == 1, "ASSERT must return 1");
. = ASSERT(symbol12 == 1, "must be 1");
ASSERT(ALIGN(0x38, 16) == 0x40, "ALIGN value is incorrect");
ASSERT(ALIGN(0x38, 18) == 0x48, "ALIGN value is incorrect");
