.section .text, "ax", @progbits
.globl cross_object_func
.type cross_object_func, @function
cross_object_func:
    li a0, 42
    ret
.size cross_object_func, .-cross_object_func
