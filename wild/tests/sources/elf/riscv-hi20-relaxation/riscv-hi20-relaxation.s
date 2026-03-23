/*
//#Arch: riscv64
//#CompArgs: -march=rv64gc
//#LinkArgs: -nostdlib -static --relax
//#Object:riscv-hi20-relaxation-1.s
//#ExpectSym:load_value size=8
*/

.section .text, "ax", @progbits

.globl _start
.type _start, @function
_start:
    call load_value
    # Verify that load_value returned the expected value (0xf00).
    li t0, 0xf00
    bne a0, t0, .Lfail
    li a0, 42
    li a7, 93
    ecall
.Lfail:
    li a0, 1
    li a7, 93
    ecall
.size _start, .-_start

.globl load_value
.type load_value, @function
load_value:
    lui a0, %hi(abs_sym)
    add a0, a0, %lo(abs_sym)
    ret
.size load_value, .-load_value
