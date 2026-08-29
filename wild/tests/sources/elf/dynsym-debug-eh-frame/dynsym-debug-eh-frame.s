/*
//#Arch:x86_64
//#LinkArgs:-shared --export-dynamic -z now
//#RunEnabled:false
//#ReferenceLinkers:bfd,lld
//#DiffMatchAny:true
//#ExpectDynSym:debug_symbol section=".debug_info",size=1
//#ExpectDynSym:frame_symbol section=".eh_frame",size=4
*/

.section .debug_info, "", @progbits
.globl debug_symbol
.type debug_symbol, @object
debug_symbol:
    .byte 0
.size debug_symbol, .-debug_symbol

.section .eh_frame, "a", @progbits
.globl frame_symbol
.type frame_symbol, @object
frame_symbol:
    .long 0
.size frame_symbol, .-frame_symbol
