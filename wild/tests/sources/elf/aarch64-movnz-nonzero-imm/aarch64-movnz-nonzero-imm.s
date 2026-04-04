/*
//#Arch: aarch64
//#LinkArgs: -nostdlib -static
*/

.section .text, "ax", @progbits

.globl target
.type target, @function
target:
    nop
.size target, .-target

# Padding so the negative offset is large enough to be unambiguous.
# 256 nops = 1024 bytes.
.rept 256
    nop
.endr

.globl _start
.type _start, @function
_start:
    .reloc ., R_AARCH64_MOVW_PREL_G0, target
    movz x0, #0x1234

    # If x0 >= 0 (MOVZ was wrongly kept), branch to failure.
    tbz x0, #63, .Lfail

    mov x0, #42
    mov x8, #93
    svc #0

.Lfail:
    mov x0, #1
    mov x8, #93
    svc #0
.size _start, .-_start
