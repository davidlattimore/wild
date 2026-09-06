ENTRY(_start)

abs_global = ABSOLUTE(0x1000);
abs_global_calc = ABSOLUTE(0x1000 + 0x500);

SECTIONS
{
    . = 0x400000;
    .text : {
        text_start = .;
        a = . + 0x20;
        b = . + 0x10;

        abs_const = ABSOLUTE(0x500);
        abs_dot = ABSOLUTE(.);
        abs_sym_a = ABSOLUTE(a);
        abs_sum_two = ABSOLUTE(ABSOLUTE(a) + ABSOLUTE(b));
        abs_max_func = ABSOLUTE(MAX(a, b));
        abs_nested = ABSOLUTE(ABSOLUTE(a));

        ASSERT(a == ABSOLUTE(text_start) + 0x20, "a failed");

        ASSERT(abs_global == 0x1000, "abs_global failed");
        ASSERT(abs_global_calc == 0x1500, "abs_global_calc failed");
        ASSERT(abs_const == 0x500, "abs_const failed");

        ASSERT(abs_dot == ABSOLUTE(text_start), "abs_dot failed");
        ASSERT(abs_dot != text_start, "abs_dot failed");
        ASSERT((abs_dot * 2) == (ABSOLUTE(text_start) * 2), "abs_dot failed");
        ASSERT((abs_dot * 2) != (text_start * 2), "abs_dot failed");

        ASSERT(abs_sym_a == ABSOLUTE(text_start) + 0x20, "abs_sym_a failed");
        ASSERT(abs_sym_a != text_start + 0x20, "abs_sym_a failed");

        ASSERT(abs_sum_two == ABSOLUTE(text_start) * 2 + 0x30, "abs_sum_two failed");
        ASSERT(abs_sum_two != text_start * 2 + 0x30, "abs_sum_two failed");

        ASSERT(abs_max_func == ABSOLUTE(text_start) + 0x20, "abs_max_func failed");
        ASSERT(abs_max_func != text_start + 0x20, "abs_max_func failed");

        ASSERT(abs_nested == ABSOLUTE(text_start) + 0x20, "abs_nested failed");

        *(.text)
    }

    . = 0x600000;
    .data : {
        data_start = .;

        ASSERT(abs_const == 0x500, "abs_const failed");

        *(.data .data.*)
    }

    .bss : {
        *(.bss .bss.*)
    }
}
