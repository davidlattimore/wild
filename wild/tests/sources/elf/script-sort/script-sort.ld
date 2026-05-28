ENTRY(_start)

SECTIONS
{
    /* Load at standard x86_64 executable address */
    . = 0x400000;

    .text : {
        *(.text)
        
        /* Protect our harvested sections from the GC! */
        KEEP(*(SORT(.text.*)))
    }
}
