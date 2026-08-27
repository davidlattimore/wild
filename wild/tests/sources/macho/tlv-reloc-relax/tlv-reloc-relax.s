//#Arch:aarch64
//#RunEnabled:false
//#DiffEnabled:false
//#ExpectSection:__thread_vars
//#ExpectSectionBytes:__text=0x00600091 4..8

.section __DATA,__thread_data,thread_local_regular
.p2align 2
_first$tlv$init:
    .long 1
_second$tlv$init:
    .long 2

.section __DATA,__thread_vars,thread_local_variables
.p2align 3
.globl _first
_first:
    .quad __tlv_bootstrap
    .quad 0
    .quad _first$tlv$init

.globl _second
_second:
    .quad __tlv_bootstrap
    .quad 0
    .quad _second$tlv$init

.text
.p2align 2
.globl _main
_main:
    adrp x0, _second@TLVPPAGE
    ldr x0, [x0, _second@TLVPPAGEOFF]
    ret
