//#AbstractConfig:default
//#Object:runtime.c
//#Arch: x86_64

//#Config:error:default
//#SkipLinker:ld
//#ExpectError:requires executable stack, but -z execstack is not specified

//#Config:allowed:default
//#LinkArgs:-z execstack

.globl _start
_start:
    mov     $42, %rdi
    call    exit_syscall

.section .note.GNU-stack,"x",@progbits
