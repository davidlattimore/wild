.section .text, "ax", @progbits
.globl conflict_func
.type conflict_func, @function
conflict_func:
    li a0, 1
    ret
.size conflict_func, .-conflict_func
