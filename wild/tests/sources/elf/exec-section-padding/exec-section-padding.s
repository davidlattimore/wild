//#ReferenceLinkers:lld
//#Arch:x86_64
//#ExpectSectionBytes:.text=0x48c7c03c000000c3cccccccccccccccc 0..16

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
