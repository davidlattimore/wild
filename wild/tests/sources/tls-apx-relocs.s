//#Object:runtime.c
//#RunEnabled:false
//#LinkArgs:-z noexecstack
//#EnableLinker:lld
//#Arch: x86_64

.section .tbss,"awT",@nobits
.globl tls0
tls0:
.zero 1024

.section .text
.globl _start
_start:

# R_X86_64_CODE_4_GOTTPOFF
	movq tls0@GOTTPOFF(%rip), %r16
	movq tls0@GOTTPOFF(%rip), %r20
	addq tls0@GOTTPOFF(%rip), %r16
	addq tls0@GOTTPOFF(%rip), %r28

# R_X86_64_CODE_6_GOTTPOFF
	addq tls0@GOTTPOFF(%rip), %r16, %r16
	addq tls0@GOTTPOFF(%rip), %r28, %r28
	addq %r16, tls0@GOTTPOFF(%rip), %r16
	addq tls0@GOTTPOFF(%rip), %r16, %r16
	{nf} addq %r8, tls0@GOTTPOFF(%rip), %r16
	{nf} addq tls0@GOTTPOFF(%rip), %rax, %r12
	{nf} addq tls0@GOTTPOFF(%rip), %r12

# R_X86_64_CODE_4_GOTPCRELX
	mov tls0@GOTPCREL(%rip), %r16
	mov tls0@GOTPCREL(%rip), %r28

# R_X86_64_CODE_4_GOTPC32_TLSDESC
	leaq tls0@TLSDESC(%rip), %r16
	leaq tls0@TLSDESC(%rip), %r30

    call exit_syscall
