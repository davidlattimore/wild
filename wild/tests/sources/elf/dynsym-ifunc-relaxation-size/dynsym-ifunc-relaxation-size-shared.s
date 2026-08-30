.section .text, "ax", @progbits
.globl shared_func
.type shared_func, @function
shared_func:
    ret
.size shared_func, .-shared_func
