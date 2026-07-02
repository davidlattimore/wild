SECTIONS
{
    . = 0x120000;
    val1 = .;
}

ASSERT(val1 == 0x120000, "val1 must be 0x120000")
