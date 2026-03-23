.section .init,"ax",@progbits
    add    $0x8, %rsp
    mov    $7, %rax
    ret

.section .fini,"ax",@progbits
    add    $0x8, %rsp
    mov    $9, %rax
    ret
