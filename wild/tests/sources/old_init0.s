.section .init,"ax",@progbits
.p2align 2
.globl _init
_init:
    endbr64
    sub    $0x8,%rsp
    nop

.section .fini,"ax",@progbits
.p2align 2
.globl _fini
_fini:
    endbr64
    sub    $0x8,%rsp
    nop
