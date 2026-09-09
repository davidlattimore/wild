// Verify that --image-base sets the load address of the output binary.
// Also verifies that a warning is emitted when the address is not page-aligned.
//#AbstractConfig:default
//#Mode:static
//#ReferenceLinkers:
//#RunEnabled:false

//#Config:aligned:default
//#LinkArgs:--image-base=0x10000000
//#ExpectSym:__executable_start address=0x10000000

//#Config:unaligned:default
//#LinkArgs:--image-base=0x10000001
//#ExpectWarningWild:--image-base: address isn't multiple of page size: 0x10000001

.globl _start
_start:
  ret
