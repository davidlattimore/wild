/*
//#Arch: riscv64
//#CompArgs: -march=rv64gc
//#LinkArgs: -nostdlib -static --gc-sections
//#NoSym:unused_func
//#ExpectSym:_start
*/

.section .text._start,"ax",@progbits
.globl _start
.type _start, @function
_start:
.LFB0:
        li      a7, 93
        li      a0, 42
        ecall
.LFE0:
        .size _start, .-_start
        .section .text.unused_func,"ax",@progbits
        .globl unused_func
        .type unused_func, @function

unused_func:
.LFB1:
        ret
.LFE1:
        .size unused_func, .-unused_func
        .section .debug_aranges,"",@progbits
        .8byte  .LFB0
        .8byte  .LFE0 - .LFB0
        .8byte  .LFB1
        .8byte  .LFE1 - .LFB1
