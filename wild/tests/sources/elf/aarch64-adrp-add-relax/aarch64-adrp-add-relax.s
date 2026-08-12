// This verifies that Wild relaxes ADRP+ADD to NOP+ADR when the symbol is
// within ADR range and registers match, but keeps ADRP+ADD when:
// - the destination registers differ (x2 vs x3 in third pair)
// - the second relocation references a different symbol (fourth pair)
// - the second relocation is not ADD (fifth pair: ADRP+ADRP)
// We use lld as reference linker since GNU ld does not implement this relaxation.
//#Arch:aarch64
//#Mode:static
//#ReferenceLinkers:lld
//#LinkArgs:--no-gc-sections -Ttext=0x200ffc
//#RunEnabled:false
//#DiffIgnore:file-header.entry
//#ExpectSectionBytes:.text=0x1f2003d5 0..4
//#ExpectSectionBytes:.text=0x1f2003d5 8..12

.globl _start
_start:
    adrp x30, x
    add  x30, x30, :lo12:x     // Relaxed (same register, same symbol, in range)
    adrp x1, x
    add  x1, x1, :lo12:x       // Relaxed (same register, same symbol, in range)
    adrp x2, x
    add  x3, x2, :lo12:x       // NOT relaxed (different dest register x3 vs x2)
    adrp x4, x
    add  x4, x4, :lo12:y       // NOT relaxed (different symbol: x vs y)
    adrp x5, x
    adrp x5, x                  // NOT relaxed (second reloc is not ADD)

.globl x
x:
    .word 0

.globl y
y:
    .word 0
.data
