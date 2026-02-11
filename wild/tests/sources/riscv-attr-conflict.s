/*
//#Arch: riscv64
//#SkipLinker:ld
//#CompArgs:-march=rv64imafc -mabi=lp64
//#Object:riscv-attr-conflict-1.s:-march=rv64imac_zfinx -mabi=lp64
//#ExpectError:'f'.*incompatible.*'zfinx'
*/

.section .text, "ax", @progbits
.globl _start
.type _start, @function
_start:
    li a0, 42
    li a7, 93
    ecall
.size _start, .-_start
