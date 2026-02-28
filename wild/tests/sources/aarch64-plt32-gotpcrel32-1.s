.section .text, "ax", @progbits

.globl target_func
.type target_func, @function
target_func:
    mov x0, #100
    ret
.size target_func, .-target_func
