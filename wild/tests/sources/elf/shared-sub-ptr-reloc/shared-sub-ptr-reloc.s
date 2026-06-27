//#Arch:x86_64
//#Mode:dynamic
//#LinkArgs:-shared --no-gc-sections
//#ExpectError:R_X86_64_8
.global foo
.data
.byte foo
.short foo
.byte foo - .
.short foo - .
