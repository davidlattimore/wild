.section .eh_frame,"a",@progbits
.long 0

after_terminator:
.long after_terminator_end - after_terminator_start
after_terminator_start:
.long 0
.ascii "SHOULD_NOT_APPEAR_IN_BINARY"
after_terminator_end:
