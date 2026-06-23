ENTRY(_start)

SECTIONS
{
    . = 0x401000;

    .text : {
        *(.text)
        
        *(SORT(.text.sort.*))
        KEEP(*(SORT(.text.kept.*)))
        *(SORT(.text.drop.*))
    }

    /* plz ensure valid alignment for subsequent sections */

    . = 0x410000;

    .eh_frame : { *(.eh_frame) }
    .note.gnu.property : { *(.note.gnu.property) }

    PROVIDE(__global_pointer$ = .);
}
