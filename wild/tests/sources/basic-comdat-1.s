.section .data.foo1,"awG",@progbits,foobar,comdat
.globl foo1
.type foo1, @object
.size foo1, 4
foo1:
.long 42

.section .data.aaa1,"awG",@progbits,abc,comdat
.globl aaa1
.type aaa1, @object
.size aaa1, 4
aaa1:
.long 42
