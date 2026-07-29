//#AbstractConfig:default
//#RunEnabled:false
//#ReferenceLinkers:lld
//#Arch: x86_64

//#Config:output-format:default
//#LinkerScript:linker-script-output-format.ld

//#Config:with_eb:default
//#LinkArgs:-EB
//#LinkerScript:linker-script-output-format-eb.ld

//#Config:with_el:default
//#LinkArgs:-EL
//#LinkerScript:linker-script-output-format-el.ld

//#Config:unsuppported:default
//#ReferenceLinkers:
//#LinkerScript:linker-script-output-format-unsupported.ld
//#ExpectError:elf32-i386 is not yet supported

//#Config:invalid:default
//#ReferenceLinkers:
//#LinkerScript:linker-script-output-format-invalid.ld
//#ExpectError:Setting the output format using OUTPUT_FORMAT is currently unsupported

void _start() {}
