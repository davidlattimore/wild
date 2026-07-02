SECTIONS
{
    . = ADDR(.data);
    val2 = .;
}

ASSERT(val2 == 0x800000, "val2 must be 0x800000")
