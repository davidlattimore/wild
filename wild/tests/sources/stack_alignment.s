// TODO: Consider if we want to keep this test. It makes sure that we can run a movaps instruction
// on a stack frame. This will segfault if the stack isn't correctly aligned to 16 bytes.

//#Object:exit.c
//#LinkArgs:-z noexecstack
//#EnableLinker:lld
//#Arch: x86_64

.globl _start
_start:
    endbr64
    movaps 0x10(%rsp),%xmm1
    mov $42,%rdi
    call exit_syscall
