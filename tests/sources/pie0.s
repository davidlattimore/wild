.section .text, "ax", @progbits
.align 8

.globl _start
_start:
    mov %rsp, %rdi
    jmp _start_c
