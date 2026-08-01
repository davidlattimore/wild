// Test that GNU property notes are correctly merged:
// - OR within same file (accumulate features)
// - AND across files (intersection of features)
//#Arch:aarch64
//#Mode:static
//#LinkArgs:--no-gc-sections
//#Relocatable:aarch64-gnu-property-merge-input.s
//#RunEnabled:false

.globl _start
_start:
    ret
