// Test that Wild relaxes the -z noplt form of TLS GD (indirect call to
// __tls_get_addr via GOTPCREL) to Local Exec, matching the relaxation
// already applied to the regular (PLT) form. Both lld and GNU ld
// correctly relax this pattern.
//#Arch:x86_64
//#LinkArgs:-nostdlib --no-gc-sections
//#ReferenceLinkers:lld,bfd
//#RunEnabled:false
.globl _start
_start:
    .byte 0x66
    leaq tlsvar@tlsgd(%rip), %rdi
    .byte 0x66
    .byte 0x48
    call *__tls_get_addr@GOTPCREL(%rip)
    ret

.section .tbss,"awT",@nobits
.globl tlsvar
tlsvar:
    .long 0
