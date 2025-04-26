/* For some reason, GAS on riscv64 does not support '//' comments.
//#Object:basic-comdat-1.s
//#RunEnabled:false
//#Static:false
//#LinkArgs:-shared -z now
//#DiffIgnore:section.got
//#DiffIgnore:segment.GNU_STACK.alignment
//#DiffIgnore:segment.GNU_STACK.flags
*/

.section .data.foo1,"awG",@progbits,foobar,comdat
.globl foo1
.type foo1, @object
.size foo1, 4
foo1:
.long 42

.section .data.foo2,"awG",@progbits,foobar,comdat
.globl foo2
.type foo2, @object
.size foo2, 4
foo2:
.long 42

.section .data.aaa1,"awG",@progbits,abc,comdat
.globl aaa1
.type aaa1, @object
.size aaa1, 4
aaa1:
.long 42
