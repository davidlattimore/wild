.option relax

.section .text.relax,"ax",@progbits
.global relax_entry
.type relax_entry, @function
relax_entry:
    call relax_target

.global after_relaxed_call
.type after_relaxed_call, @function
after_relaxed_call:
    ret

.type relax_target, @function
relax_target:
    ret

.section .data,"aw",@progbits
.byte 1
