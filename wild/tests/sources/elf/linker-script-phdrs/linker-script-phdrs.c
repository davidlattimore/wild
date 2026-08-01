//#AbstractConfig:default
//#Mode:dynamic
//#RunEnabled:false
//#CompArgs:-fPIE -fPIC
//#DiffIgnore:section.got
// Skip the .custom section, since it is forcefully excluded from any segments.
//#DiffIgnore:section-diff-failed..custom

//#Config:nophdrs:default
//#LinkArgs:-shared -z now -T ./linker-script-phdrs.ld --defsym=is_riscv=0
//#ExpectProgramHeader:LOAD flags=RX,sections=[.text]
//#ExpectProgramHeader:DYNAMIC flags=RW,sections=[.dynamic,*]
//#ExpectProgramHeader:LOAD flags=RW,sections=[.bss,*]
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
//#ExpectProgramHeader:LOAD flags=RWX,sections=[.text,.rodata,.dynamic,*]

//#Config:single-load-with-flag:default
//#LinkArgs:-shared -z now -T ./linker-script-phdrs-single-load-with-flag.ld
//#ExpectProgramHeader:LOAD flags=RX,sections=[.text,.rodata,.dynamic,*]

//#Config:no-load:default
//#LinkArgs:-shared -z now -T ./linker-script-phdrs-no-load.ld
//#ExpectErrorWild:Missing LOAD PHDR in linker script

//#Config:with-pt-phdr:default
//#ExpectProgramHeader:PHDR sections=[],offset=0x40
//#ExpectProgramHeader:LOAD flags=RX,sections=[.text,*],offset=0x0
//#LinkArgs:-shared -z now -T ./linker-script-phdrs-with-pt-phdr.ld

//#Config:discontinuous:default
//#LinkArgs:-shared -z now -T ./linker-script-phdrs-discontinuous.ld
//#ExpectError:PHDRS and FILEHDR are not supported when prior PT_LOAD headers lack them

//#Config:non-load-with-headers:default
//#LinkArgs:-shared -z now -T ./linker-script-phdrs-non-load.ld
//#ExpectError:(?i-u)non-load segment [0-9]+ includes file header and/or program header

const char message[] = "Hello PHDRS";
char message2[10];

int foo(void) { return message2[0] + 42; }

const char* bar() { return &message[0]; }

__attribute__((used, section(".custom"))) int baz() { return 42; }
