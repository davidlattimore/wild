ENTRY(begin_here)

offset1 = 0x200;

SECTIONS
{
    . = 0x600000;

	offset3 = 0x500;

    .custom : {
        *(.custom.1)
		offset2 = 0x40;
        *(.custom.2)
        . = custom_two + 0x100;
        *(.custom.3)
		before_offset2 = .;
		. += offset2;
		after_offset2_custom = .;
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

	. += offset1;

	after_offset1 = .;

	. += offset2;

	after_offset2 = .;

	. += offset3;

	after_offset3 = .;

	. += offset4;

	after_offset4 = .;

    . = abs_symbol;

    after_abs = .;

    .data : {
        *(.data)
		data_offset = .;
		. += offset1;
		after_offset1_data = .;

		. += offset2;
		after_offset2_data = .;

		. += offset3;
		after_offset3_data = .;
        *(.data.*)

		. += offset4;
		after_offset4_data = .;
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
ASSERT(after_offset1 == after_abs_between + offset1, "after_offset1 is incorrect");
ASSERT(after_offset2 == after_offset1 + offset2, "after_offset2 is incorrect");
ASSERT(after_offset3 == after_offset2 + offset3, "after_offset3 is incorrect");
ASSERT(after_offset4 == after_offset3 + offset4, "after_offset3 is incorrect");
ASSERT(after_offset1_data == data_offset + offset1, "after_offset1_data is incorrect");
ASSERT(after_offset2_data == after_offset1_data + offset2 + after_abs, "after_offset2_data is incorrect");
ASSERT(after_offset3_data == after_offset2_data + offset3, "after_offset3_data is incorrect");
ASSERT(after_offset4_data == after_offset3_data + offset4, "after_offset3_data is incorrect");
ASSERT(after_offset2_custom == before_offset2 + 0x40, "after_offset2_custom is incorrect");
