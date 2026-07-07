.section .text.frame_after_terminator,"ax",@progbits
.globl frame_after_terminator
.type frame_after_terminator, @function
frame_after_terminator:
.cfi_startproc
.byte 0
.cfi_endproc
.size frame_after_terminator, . - frame_after_terminator
