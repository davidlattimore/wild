/*
The symbol `foo` is interposable and we have a relocation that refers to it in a non-writable
section. This is OK though, because the section containing the relocation is non-alloc.

The symbol `bar` is undefined. Similarly, because the relocation is in a non-alloc section, no
dynamic relocation is produced.

//#CompArgs:-fPIC
//#LinkArgs:-shared -z now -z text
//#RunEnabled:false
//#DiffIgnore:section.got
*/

	.text
.Ltext0:
	.globl	foo
	.section	.tdata,"awT",@progbits
	.align	8
	.type	foo, @object
	.size	foo, 8
foo:
	.8byte	42

	.globl  bar
	.type	bar, @object

	.section	.extra,"R",@progbits
	.8byte	foo
	.8byte  bar
