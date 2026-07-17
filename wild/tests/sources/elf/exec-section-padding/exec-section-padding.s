//#AbstractConfig:default
//#ReferenceLinkers:lld
//#Arch:x86_64

//#Config:nop:default
//#ExpectSectionBytes:.text=0x48c7c03c000000c3cccccccccccccccc 0..16

//#Config:with-linkerscript:default
//#LinkerScript:exec-section-padding.ld
//#ExpectSectionBytes:.text=0x48c7c03c000000c39090909090909090 0..16
//#ExpectSectionBytes:.text=0x90909090909090909090909090909090 16..32
//#RunEnabled:false

.section .text.1
.balign 16
.globl foo
foo:
    mov $60, %rax
    ret

.section .text.2
.balign 16
.globl _start
_start:
    call foo
    xor %rdi, %rdi
    mov $42, %edi
    syscall
    ret
