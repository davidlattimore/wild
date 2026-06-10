// Test that R_X86_64_PC32 to absolute address is handled for non-PIE executables.
// `call 0` generates R_X86_64_PC32 with no symbol and addend=-4.
// lld and GNU ld handle this by computing a PC-relative offset to address 0.
//#Arch:x86_64
//#LinkArgs:-nostdlib -z noexecstack
//#Mode:static
//#RunEnabled:false

.text
.globl _start
.type _start, @function
_start:
    callq 0
    ret
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
