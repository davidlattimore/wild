/*

This test is similar to source-info-from-debug, but due to being asm, can more reliably pick up some
problems that test fails to detect.

//#CompArgs:-g
//#ExpectError:the-answer:42
*/

.file 1 "the-answer"

.section .text
.globl _start
.type _start, @function
_start:
        .loc 1 2
        nop
        .loc 1 12
        nop
        .loc 1 22
        nop
        .loc 1 32
        nop
        .loc 1 42
        nop
        .8byte undefined
.size _start, .-_start
