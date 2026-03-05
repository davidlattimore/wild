/*
//#Arch: riscv64
//#CompArgs: -march=rv64gc
//#LinkArgs: -nostdlib -static --relax
//#Object:riscv-hi20-lui-deletion-1.s
//#ExpectSym:load_zero size=6
//#ExpectSym:load_small size=6
*/

.section .text, "ax", @progbits

.globl _start
.type _start, @function
_start:
    call load_zero
    bnez a0, .Lfail

    call load_small
    li t0, 0x7ff
    bne a0, t0, .Lfail

    li a0, 42
    li a7, 93
    ecall
.Lfail:
    li a0, 1
    li a7, 93
    ecall
.size _start, .-_start

.globl load_zero
.type load_zero, @function
load_zero:
    lui a0, %hi(zero_sym)
    add a0, a0, %lo(zero_sym)
    ret
.size load_zero, .-load_zero

.globl load_small
.type load_small, @function
load_small:
    lui a0, %hi(small_sym)
    add a0, a0, %lo(small_sym)
    ret
.size load_small, .-load_small
