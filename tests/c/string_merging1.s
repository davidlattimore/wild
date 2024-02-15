.section .rodata.strings, "aSM", @progbits, 1
.align 1

.globl s1h
s1h: .ascii "Hello\0"

.globl s1w
s1w: .ascii "World\0"

// Put some regular data in .rodata with alignment >1 to make sure that doesn't mess up our merged
// string offsets.

.section .rodata, "a", @progbits
.align 8

.globl a1
a1:
.ascii "Aligned\0"
