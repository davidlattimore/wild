// Test that Wild relaxes the -z noplt form of TLS GD to Initial Exec
// when the TLS symbol is in a shared object. The indirect call form
// (call *__tls_get_addr@GOTPCREL(%rip), encoded as 0xff 0x15) must
// relax to IE (mov %fs:0,%rax; add offset(%rip),%rax) like the
// regular PLT call form. Both lld and GNU ld handle this correctly.
//#Arch:x86_64
//#Mode:dynamic
//#LinkArgs:--no-gc-sections
//#Shared:tls-gd-noplt-ie-shared.s
//#SoSingleLinker:wild
//#ReferenceLinkers:lld,bfd
//#RunEnabled:false
//#DiffIgnore:.dynamic.DT_FLAGS_1.NOW
.globl _start
_start:
    .byte 0x66
    leaq tlsvar@tlsgd(%rip), %rdi
    .byte 0x66
    .byte 0x48
    call *__tls_get_addr@GOTPCREL(%rip)
    ret
