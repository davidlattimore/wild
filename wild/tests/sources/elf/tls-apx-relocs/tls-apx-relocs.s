//#Object:runtime.c
//#RunEnabled:false
//#LinkArgs:-z noexecstack
//#Arch: x86_64

.section .tbss,"awT",@nobits
.globl tls
tls:
.zero 1024

.section .text
.globl _start
.type foo, @function
foo:
    endbr64
    mov     $2, %rax
    ret

_start:

# R_X86_64_CODE_4_GOTTPOFF
	movq tls@GOTTPOFF(%rip), %r16
	movq tls@GOTTPOFF(%rip), %r20
	addq tls@GOTTPOFF(%rip), %r16
	addq tls@GOTTPOFF(%rip), %r28

# R_X86_64_CODE_6_GOTTPOFF
	addq tls@GOTTPOFF(%rip), %r16, %r16
	addq tls@GOTTPOFF(%rip), %r28, %r28
	addq %r16, tls@GOTTPOFF(%rip), %r16
	addq tls@GOTTPOFF(%rip), %r16, %r16

# R_X86_64_CODE_4_GOTPCRELX
	mov foo@GOTPCREL(%rip), %r16
	mov foo@GOTPCREL(%rip), %r28

# R_X86_64_CODE_4_GOTPC32_TLSDESC
	leaq tls@TLSDESC(%rip), %r16
	leaq tls@TLSDESC(%rip), %r30

    call exit_syscall
