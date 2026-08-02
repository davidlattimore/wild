ENTRY(_start)

SECTIONS
{
    . = 0x401000;

    .text : {
        *(.text)
        
        *(SORT(.text.sort.*))
        KEEP(*(SORT(.text.kept.*)))
        *(SORT_BY_NAME(.text.drop.*))
        *(SORT_BY_ALIGNMENT(.text.align.*))
    }

    /* Ensure valid alignment for subsequent sections */

    . = 0x420000;

    .eh_frame : { *(.eh_frame) }
    .note.gnu.property : { *(.note.gnu.property) }

    PROVIDE(__global_pointer$ = .);
}
