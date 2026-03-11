//#LinkArgs:-shared -z now
//#RunEnabled:false
//#DiffIgnore:section.got
//#ExpectSym:abs_sym address=0xCAFECAFE
//#ExpectDynSym:abs_sym address=0xCAFECAFE

// TODO: checkout those differences later
//#DiffIgnore:segment.RISCV_ATTRIBUTES.alignment
//#DiffIgnore:segment.RISCV_ATTRIBUTES.flags
//#DiffIgnore:riscv_attributes..riscv.attributes
//#DiffIgnore:riscv_attributes.arch
//#DiffIgnore:riscv_attributes.stack_align

.global abs_sym
.set abs_sym, 0xCAFECAFE
