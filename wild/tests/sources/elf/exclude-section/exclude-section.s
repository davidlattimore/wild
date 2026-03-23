/* For some reason, GAS on riscv64 does not support '//' comments.
//#Mode:dynamic
//#RunEnabled:false
//#LinkArgs:-shared --no-gc-sections -z now
//#DiffIgnore:section.got
//#DiffIgnore:segment.LOAD.RX.alignment
//#Contains:ShouldBeKept
//#DoesNotContain:ShouldBeExcluded
*/

.section .keep
.ascii "ShouldBeKept\0"

.section .exclude, "e"
.ascii "ShouldBeExcluded\0"
