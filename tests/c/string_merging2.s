.section .rodata.strings, "aSM", @progbits, 1
.align 1

.globl s2w
s2w: .ascii "World\0"

.globl s2h
s2h: .ascii "Hello\0"

.globl s2nz
s2nz: .ascii "Non-terminated"

// Define a string-merge section containing a local then make sure we can reference it.

.section .rodata.loc1, "aSM", @progbits, 1
.align 1
.loc1: .ascii "Local1\0"

.section .text, "ax", @progbits
.globl get_loc1
get_loc1:
    endbr64
    lea .loc1(%rip), %rax
    ret
