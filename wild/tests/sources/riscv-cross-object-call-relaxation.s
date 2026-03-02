/*
//#Arch: riscv64
//#CompArgs: -march=rv64gc
//#LinkArgs: -nostdlib -static --relax
//#Object:riscv-cross-object-call-relaxation-1.s
//#ExpectSym:cross_object_func
//#ExpectSym:_start size=12
*/

.section .text, "ax", @progbits
.globl _start
.type _start, @function
_start:
    call cross_object_func
    li a7, 93
    ecall
.size _start, .-_start
