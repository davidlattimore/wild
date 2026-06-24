/*
 * Tests that we can handle a relative relocation to address 0 from a
 * non-relocatable RISC-V executable.
//#Arch: riscv64
//#LinkArgs: -nostdlib -static
//#Mode: static
//#RunEnabled: false
*/
.text
.globl _start
.type _start, @function
_start:
    jal ra, 0
    ret
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
