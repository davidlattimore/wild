.section .rodata.foo, "aM", @progbits, 1
.align 1

// Test that null terminated strings in non-string sections are merged correctly.
.globl s2w
s2w: .ascii "World\0"

.section .rodata.bar, "aM", @progbits, 1
.align 1

.globl s2h
s2h: .ascii "Hello"

// Define a merge section containing a local then make sure we can reference it.

.section .rodata.loc1, "aM", @progbits, 1
.align 1
.loc1: .ascii "Local1"

.section .text, "ax", @progbits

.globl get_loc1
get_loc1:
    endbr64
    lea .loc1(%rip), %rax
    ret

// Define a getter that uses a GOT relocation to access a symbol defined in a different object file.

.globl get_s1w
get_s1w:
    endbr64
    movq s1w@GOTPCREL(%rip),%rax
    ret

// Define a getter that uses a GOT relocation to access a symbol defined in this object file.

.globl get_s2w
get_s2w:
    endbr64
    movq s2w@GOTPCREL(%rip),%rax
    ret

// Data in custom section

.section .custom1, "aM", @progbits, 1
.align 1

.globl s4h
s4h: .ascii "Hello"

.section .text, "ax", @progbits
.align 8

// Returns a pointer to s2w, but does so using a relocation that has an addend that would put us
// outside of s2w. Relocations that reference named symbols in string-merge sections shouldn't take
// the addend into account when determining which data we're referencing.
.globl get_s2w_via_offset
.type get_s2w_via_offset, @function
get_s2w_via_offset:
    endbr64
    lea s1w-100(%rip), %rax
    add $100, %rax
    ret
.size get_s2w_via_offset, .-get_s2w_via_offset
