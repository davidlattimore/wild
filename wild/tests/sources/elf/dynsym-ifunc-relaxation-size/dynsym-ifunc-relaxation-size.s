/*
//#AbstractConfig:default
//#Arch:riscv64
//#LinkerDriver:gcc
//#CompArgs:-march=rv64gc
//#Shared:dynsym-ifunc-relaxation-size-shared.s
//#RunEnabled:false
//#DiffEnabled:false

//#Config:non-pie:default
//#LinkArgs:-nostdlib -no-pie -Wl,--no-as-needed,--export-dynamic,--relax,-z,now
//#ExpectDynSym:relaxed_ifunc size=6

//#Config:pie:default
//#LinkArgs:-nostdlib -pie -Wl,--no-as-needed,--export-dynamic,--relax,-z,now
//#ExpectDynSym:relaxed_ifunc section=".text",size=6
*/

.section .text, "ax", @progbits
.globl _start
.type _start, @function
_start:
    call relaxed_ifunc
    ret
.size _start, .-_start

.globl relaxed_ifunc
.type relaxed_ifunc, @gnu_indirect_function
relaxed_ifunc:
    call nearby_func
    ret
.size relaxed_ifunc, .-relaxed_ifunc

.type nearby_func, @function
nearby_func:
    ret
.size nearby_func, .-nearby_func
