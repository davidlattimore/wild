ENTRY(_start)

SECTIONS
{
    . = 0x401000;

    .text : {
        *(.text)
        
        /* Test 1: Global sorting across files using standard ELF naming */
        *(SORT(.text.sort.*))
        
        /* Test 2: SORT with KEEP */
        KEEP(*(SORT(.text.kept.*)))

        /* Test 3: SORT without KEEP */
        *(SORT(.text.drop.*))
    }

    PROVIDE(__global_pointer$ = .);
}
