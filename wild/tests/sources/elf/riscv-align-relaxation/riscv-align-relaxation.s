/*
//#Arch: riscv64
//#CompArgs: -march=rv64gc
//#LinkArgs: -nostdlib -static
//#DiffIgnore:file-header.entry
*/

.globl _start
_start:
    la      a0, aligned_sym
    andi    a1, a0, 31
    bnez    a1, .Lfail
    li      a0, 42
    li      a7, 93
    ecall

.Lfail:
    li      a0, 1
    li      a7, 93
    ecall

.p2align 5
.globl aligned_sym
aligned_sym:
    ret
