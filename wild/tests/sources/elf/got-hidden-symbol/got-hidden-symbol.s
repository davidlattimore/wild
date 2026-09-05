// Verify that _GLOBAL_OFFSET_TABLE_ is defined as a local hidden symbol.
// It should not be visible as a global dynamic symbol.
//#Arch:aarch64
//#Mode:dynamic
//#ReferenceLinkers:lld
//#LinkArgs:--hash-style=sysv -shared
//#DiffIgnore:.dynamic.DT_FLAGS_1*
//#DiffIgnore:section.got.plt.entsize
//#RunEnabled:false
//#ExpectSym:_GLOBAL_OFFSET_TABLE_ binding=local
//#NoDynSym:_GLOBAL_OFFSET_TABLE_
.globl f
.type f, @function
f:
  adrp x0, :got:a
  ldr x0, [x0, :got_lo12:a]
  ret

.globl a
.type a, @object
.comm a, 4, 4

.globl _start
.type _start, @function
_start:
  bl f
.data
.long _GLOBAL_OFFSET_TABLE_ - .
