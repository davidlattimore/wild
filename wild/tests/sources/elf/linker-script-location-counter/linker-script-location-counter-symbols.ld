ENTRY(begin_here)

SECTIONS
{
    . = 0x600000;

    .custom : {
        *(.custom.1)
        *(.custom.2)
        . = custom_two + 0x100;
        *(.custom.3)
        . = 0x1000;
    }

    .text : {
        *(.text)
        *(.text.*)
    }

    first_lc = .;

    . = . + 0x100;

    second_lc = .;

    . = foo + 0x100000;

    after_foo = .;

    . = abs_between + 0x100;

    after_abs_between = .;

    . = abs_symbol;

    after_abs = .;

    .data : {
        *(.data)
        *(.data.*)
    }
}

ASSERT(custom_three > custom_two, ".text.3 must be placed after .text.2");
ASSERT(first_lc == ADDR(.text) + SIZEOF(.text), "first_lc is incorrect");
ASSERT(second_lc > first_lc, "second_lc must be after first_lc");
ASSERT(ADDR(.custom) <= custom_two && custom_three < ADDR(.text), ".text.3 must be placed after .text.2");
ASSERT(after_foo == foo + 0x100000, "after_foo is incorrect");
ASSERT(after_abs_between == abs_between + 0x100, "after_abs_between is incorrect");
ASSERT(after_abs == abs_symbol, "after_abs is incorrect");
ASSERT(ADDR(.data) == after_abs, ".data must start at after_abs");
