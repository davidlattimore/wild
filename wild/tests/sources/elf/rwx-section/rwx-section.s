// Test that sections with writable+executable (awx) flags are placed in an RWX LOAD segment.
// Wild should warn about RWX permissions like GNU ld does.
//#Arch:x86_64
//#Mode:static
//#RunEnabled:false
//#ExpectWarningWild:has RWX \(read\+write\+execute\) permissions

.section .wtext,"awx"
.globl _start
_start:
    ret
