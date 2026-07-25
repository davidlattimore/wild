//#AbstractConfig:default
//#Mode:dynamic
//#RunEnabled:false
//#CompArgs:-fPIE -fPIC
//#DiffIgnore:section.got

//#Config:nophdrs:default
//#LinkArgs:-shared -z now -T ./linker-script-phdrs.ld --defsym=is_riscv=0
//#ExpectProgramHeader:LOAD flags=RX,sections=[.text]
//#ExpectProgramHeader:DYNAMIC flags=RW,sections=[.dynamic,*]
//#ExpectProgramHeader:LOAD flags=RW,sections=[*]
//#ExpectProgramHeader:LOAD flags=R,sections=[.rodata,.dynamic,*]
//#ExpectProgramHeader:LOAD sections=[]
//#NoProgramHeader:PHDR
//#NoProgramHeader:NOTE
//#NoProgramHeader:GNU_STACK
//#NoProgramHeader:GNU_RELRO
//#NoProgramHeader:GNU_PROPERTY
//#SkipArch:riscv64

//#Config:riscv:nophdrs
//#Arch:riscv64
//#ExpectProgramHeader:RISCV_ATTRIBUTES flags=R,sections=[.riscv.attributes]
//#LinkArgs:-shared -z now -T ./linker-script-phdrs.ld --defsym=is_riscv=1

//#Config:single-load:default
//#LinkArgs:-shared -z now -T ./linker-script-phdrs-single-load.ld

const char message[] = "Hello PHDRS";

int foo(void) { return 42; }

const char* bar() { return &message[0]; }
