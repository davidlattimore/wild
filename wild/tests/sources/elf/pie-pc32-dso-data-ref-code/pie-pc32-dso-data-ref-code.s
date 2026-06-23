// Scenario: data section references DSO function via R_X86_64_PC32 - invalid in PIE
//#Arch:x86_64
//#Mode:dynamic
//#Shared:pie-pc32-dso-shared-fn.s
//#SoSingleLinker:wild
//#LinkArgs:-pie --no-gc-sections
//#EnableLinker:lld
//#ExpectError:R_X86_64_PC32
//#SkipLinker:ld
.global _start
_start:
    ret
.data
.long zed_fn - .
