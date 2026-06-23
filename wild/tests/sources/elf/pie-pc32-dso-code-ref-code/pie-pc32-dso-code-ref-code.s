// Scenario: code references DSO function via PLT call - valid in PIE
//#Arch:x86_64
//#Mode:dynamic
//#Shared:pie-pc32-dso-shared-fn.s
//#SoSingleLinker:wild
//#LinkArgs:-pie
//#RunEnabled:false
//#EnableLinker:lld
//#SkipLinker:ld
//#DiffIgnore:.dynamic.DT_FLAGS_1.NOW
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT
//#DiffIgnore:section.got.plt.entsize
.global _start
_start:
    call zed_fn
    ret
