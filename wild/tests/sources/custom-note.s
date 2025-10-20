/*
//#LinkArgs:-shared -z now --gc-sections
//#RunEnabled:false
//#Contains:FOOBAR
//#Contains:HELLO_WORLD
//#DiffIgnore:section.got
//#DiffIgnore:segment.RISCV_ATTRIBUTES.*
*/

.section .note.foo,"a",@note
.align 4

/* name length, desc length, type */
.long 7
.long 8
.long 1

.asciz "FOOBAR"
.align 4

.quad 0x1122334455667788
.align 4

/* Non-alloc note section */

.section .note.hello,"",@note
.align 4

/* name length, desc length, type */
.long 12
.long 8
.long 1

.asciz "HELLO_WORLD"
.align 4

.quad 0x1122334455667788
.align 4
