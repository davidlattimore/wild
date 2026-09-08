# Tests that partial linking correctly handles alignment padding after relocation sections.

//#Arch: x86_64
//#Compiler:gcc
//#LinkArgs:-r
//#RunEnabled:false
//#TestUpdateInPlace:true
//#ReferenceLinkers:bfd,lld
//#DiffEnabled:false
//#ExpectSectionBytes:.unique_marker=0x7856341200000000

.section .unique_target,"aw",@progbits
.balign 32
.zero 32

.section .rela.unique_target,"",@4
.balign 32
.quad 0, 0, 0

.section .padding,"",@progbits
.zero 8

.section .unique_marker,"aw",@progbits
.balign 32
.globl marker
marker:
.quad 0x12345678
