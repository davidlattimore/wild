/*
//#Arch: loongarch64
//#LinkArgs: -nostdlib -static --no-relax
*/

.section .text, "ax", @progbits

.globl _start
.type _start, @function
_start:
    .reloc ., R_LARCH_B26, target_func
    .4byte 0x57000c01

    addi.w  $r12, $r0, 42
    bne     $r4, $r12, .Lfail

    addi.w  $r4, $r0, 42
    addi.w  $r11, $r0, 93
    syscall 0

.Lfail:
    addi.w  $r4, $r0, 1
    addi.w  $r11, $r0, 93
    syscall 0
.size _start, .-_start

# Push target_func far away so the final resolved offset differs from the garbage immediate that was pre-encoded in the bl instruction.
.rept 16384
    nop
.endr

.globl target_func
.type target_func, @function
target_func:
    addi.w  $r4, $r0, 42
    jirl    $r0, $r1, 0
.size target_func, .-target_func
