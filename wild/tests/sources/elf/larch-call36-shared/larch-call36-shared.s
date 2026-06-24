/*
//#Config:default
//#Arch:loongarch64
//#Mode:dynamic
//#LinkArgs:-shared -z now
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT
//#RunEnabled:false
*/

.section .text, "ax", @progbits

.globl call_target
.type call_target, @function
call_target:
    addi.w  $r4, $r0, 42
    jirl    $r0, $r1, 0
.size call_target, .-call_target

.globl do_call
.type do_call, @function
do_call:
    pcaddu18i $r1, %call36(call_target)
    jirl      $r1, $r1, 0
.size do_call, .-do_call
