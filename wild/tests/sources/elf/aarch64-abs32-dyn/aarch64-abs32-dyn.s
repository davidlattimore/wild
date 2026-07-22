//#Arch:aarch64
//#Mode:dynamic
//#LinkArgs:-shared --no-gc-sections
//#ExpectError:R_AARCH64_ABS32
//#ExpectErrorWild:R_AARCH64_ABS32.*cannot be used when making a shared object
.globl hidden
.hidden hidden
hidden:
.data
.long hidden
