ENTRY(_start)

SECTIONS
{
    . = 0x401000;

    .text : {
        *(.text)
        
        /* Our custom sorted sections */
        *(SORT(.text.sort.*))
        KEEP(*(SORT(.text.kept.*)))
        *(SORT(.text.drop.*))
    }

    /* * using a quick workaround to push the metadata onto a separate 64KB page.
     * This stops lld from triggering a page protection segfault
     * to me hardcoding seemed like the only option as wild wild's parser doesn't support dynamic alignment expressions yet
     * In future, I would love to work on adding proper ALIGN support to the parser
     */
    . = 0x410000;

    .eh_frame : { *(.eh_frame) }
    .note.gnu.property : { *(.note.gnu.property) }
    .got : { *(.got) *(.got.plt) }

    PROVIDE(__global_pointer$ = .);
}
