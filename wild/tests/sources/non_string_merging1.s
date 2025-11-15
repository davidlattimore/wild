.section .rodata.foo, "aM", @progbits, 1
.align 1

.globl s1h
s1h: .ascii "Hello"

.section .rodata.bar, "aM", @progbits, 1
.align 1

.globl s1w
s1w: .ascii "World"

// Put some regular data in .rodata with alignment >1 to make sure that doesn't mess up our merged
// string offsets.

.section .rodata, "a", @progbits
.align 8

.globl a1
a1:
.ascii "Aligned"


// Another section identical to one above, but as a custom section, not the .data section. 
// It should get merged with other identical `custom1` section, but not with different sections.

.section .custom1, "aM", @progbits, 1
.align 1

.globl s3h
s3h: .ascii "Hello"

.section .custom2, "aM", @progbits, 1
.align 1

.globl noref
noref: .ascii "No reference to this string"

// Ensure that we can handle a merge section that's empty.

.section .empty, "aM", @progbits, 1
.globl in_empty_string_merge
in_empty_string_merge:
