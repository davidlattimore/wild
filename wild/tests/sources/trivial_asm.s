//#LinkArgs:-z noexecstack
//#Object:exit.c
//#Arch: x86_64

.section        .data.foo
.p2align        4, 0x0
foo:
    .quad 3



.section        .data.rel.ro,"aM",@progbits,16
.p2align        4, 0x0

.type .Ldata0, @object
.Ldata0:
    .quad foo
.size .Ldata0, .-.Ldata0

.type .Ldata1, @object
.Ldata1:
    .quad 7
.size .Ldata1, .-.Ldata1


.section .text, "ax", @progbits
.align 8

.globl _start
.type _start, @function
_start:
    mov     $101, %rdi
    mov     .Ldata0@GOTPCREL(%rip), %eax
    mov     (%rax), %rax
    mov     (%rax), %rax
    cmp     $3, %rax
    jne     exit_syscall

    mov     $42, %rdi
    call    exit_syscall
.size _start, .-_start
