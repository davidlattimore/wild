.section .text,"ax",@progbits

.type foo1, @function
foo1:
    endbr64
    mov     $2, %rax
    ret

.type foo2, @function
foo2:
    endbr64
    mov     $22, %rax
    ret

// We do a 32 bit relocation here, since at the time of writing, we don't optimise away 32 bit GOT
// references.
.globl get_foo1
.type get_foo1, @function
get_foo1:
    endbr64
    mov     foo1@GOTPCREL(%eip), %eax
    ret

.globl get_foo2
.type get_foo2, @function
get_foo2:
    endbr64
    mov     foo2@GOTPCREL(%eip), %eax
    ret
