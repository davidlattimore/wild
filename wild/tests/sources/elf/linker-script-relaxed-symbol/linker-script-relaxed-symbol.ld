ENTRY(relax_entry)

SECTIONS
{
    . = 0x10000;
    .text : {
        *(.text.relax)
        . = after_relaxed_call + 0x100;
        data_address = .;
        *(.data)
    }
}

ASSERT(data_address == after_relaxed_call + 0x100, "relaxed symbol address is incorrect");
