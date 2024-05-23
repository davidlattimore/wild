// The C compiler seems to always reference local symbols by offsets from the section containing the
// symbol. We want to make sure that actual symbol references work properly too.

// We don't apply the M flag to our .rodata
//#DiffIgnore:section.rodata.flags
//#Object:exit.c

.section        .rodata.x,"aM",@progbits,16
.p2align        4, 0x0

vvv1:
    .quad 8

vvv2:
    .quad 9

.section .text._start,"ax",@progbits

.globl _start
.type _start, @function
_start:
    endbr64

    movq    vvv1(%rip), %rax
    cmpq    $8, %rax
    jne     fail

    movq    vvv2(%rip), %rax
    cmpq    $9, %rax
    jne     fail

    mov     $42,%rdi
    call    exit_syscall

fail:
    movq    $99, %rdi
    call    exit_syscall
