// Scenario: code references DSO STT_FUNC symbol via R_X86_64_PC32 in PIE.
// Wild and lld create a canonical PLT entry and link successfully.
// GNU ld errors on R_X86_64_PC32 against DSO symbol in PIE, so skip it.
//#Arch:x86_64
//#Mode:dynamic
//#Shared:pie-pc32-dso-shared.s
//#SoSingleLinker:wild
//#LinkArgs:-pie --no-gc-sections
//#SkipLinker:ld
//#RunEnabled:false
.global _start
_start:
    mov zed_fn - ., %eax
    ret
