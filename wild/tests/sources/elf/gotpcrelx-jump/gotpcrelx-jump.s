//#Config:default
//#Arch:x86_64
//#LinkArgs:-nostdlib --no-gc-sections -z noexecstack
//#RunEnabled:false

//#Config:malfunction-no-jmp-indirect-to-relative:default
//#Malfunction:no-jmp-indirect-to-relative

.globl _start
_start:
    jmp *target@GOTPCREL(%rip)

.hidden target
target:
    ret
