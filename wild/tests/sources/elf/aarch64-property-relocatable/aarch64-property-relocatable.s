// Test that Wild doesn't panic when doing a relocatable link with an object
// containing .note.gnu.property section (which has $d mapping symbol).
// Previously Wild panicked with "Tried to copy a symbol in a section we didn't load"
// for the $d mapping symbol in the .note.gnu.property section.
//#Arch:aarch64
//#Mode:static
//#LinkArgs:--no-gc-sections
//#Relocatable:aarch64-property-relocatable-input.s
//#RunEnabled:false

.globl _start
_start:
    ret
