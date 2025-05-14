.globl preinit

.section .preinit_array,"aw",@preinit_array
.p2align 3
.quad preinit

.section    .note.GNU-stack,"",@progbits
