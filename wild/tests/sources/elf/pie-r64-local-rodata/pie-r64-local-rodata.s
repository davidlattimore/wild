//#Arch:x86_64
//#Mode:dynamic
//#LinkArgs:-pie
//#EnableLinker:lld
//#ExpectError:R_X86_64_64
//#SkipLinker:ld
.global _start, foo, rodata_ref
_start:
    lea rodata_ref(%rip), %rax
    ret
foo:
    ret
.section .rodata
rodata_ref:
.quad _start
.quad foo
