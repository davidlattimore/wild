// This tests makes sure that we're able to handle a retained, non-alloc section.

//#LinkArgs:-z noexecstack
//#Object:exit.c

.section .nonloadable, "R", @progbits
    .asciz "Hello, World!"

.section .text, "ax", @progbits
.align 8

.globl _start
.type _start, @function
_start:
    mov     $42, %rdi
    call    exit_syscall
.size _start, .-_start
