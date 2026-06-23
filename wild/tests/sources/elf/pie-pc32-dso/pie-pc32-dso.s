// Test that R_X86_64_PC32 to a DSO symbol in a non-executable section errors in PIE output.
// lld errors with "recompile with -fPIC". Valid in .text (PLT call) but not in .data.
//#Arch:x86_64
//#Mode:dynamic
//#Shared:pie-pc32-dso-shared.s
//#LinkArgs:-pie --no-gc-sections
//#ExpectErrorWild:R_X86_64_PC32
//#SkipLinker:ld

.global _start
_start:
    ret

.data
.long zed - .
