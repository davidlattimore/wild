// Scenario: code references DSO data symbol via R_X86_64_PC32 - invalid in PIE.
// SkipLinker:lld because lld creates a canonical PLT entry for R_X86_64_PC32 to
// STT_FUNC DSO symbols and succeeds, while Wild doesn't support canonical PLT and errors.
// This case will be revisited when canonical PLT support is added to Wild.
//#Arch:x86_64
//#Mode:dynamic
//#Shared:pie-pc32-dso-shared.s
//#SoSingleLinker:wild
//#LinkArgs:-pie --no-gc-sections
//#ExpectErrorWild:R_X86_64_PC32
//#SkipLinker:ld
//#SkipLinker:lld
.global _start
_start:
    mov zed_fn - ., %eax
    ret
