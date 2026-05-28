ENTRY(_start)

SECTIONS
{
    /* Start at base + 4KB to safely leave room for ELF headers without using math */
    . = 0x401000;

    .text : {
        *(.text)
        
        /* Protect our harvested sections from the GC! */
        KEEP(*(SORT(.text.*)))
    }
}
