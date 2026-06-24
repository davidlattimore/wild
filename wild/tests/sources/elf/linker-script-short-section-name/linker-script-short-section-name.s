//#Arch:x86_64
//#LinkerScript:linker-script-short-section-name.ld
//#Mode:static
//#RunEnabled:false
//#SkipLinker:ld

.section foo
.long 0

.text
.globl _start
_start:
    ret
