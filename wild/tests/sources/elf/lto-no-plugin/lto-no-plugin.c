// Checks what we do if we try to link LTO inputs when no plugin is supplied.

//#AbstractConfig:default
//#ReferenceLinkers:
//#ExpectError:linker plugin was not supplied
//#CompArgs:-flto
//#RequiresLinkerPlugin:true

//#Config:gcc:default
//#Compiler:gcc

//#Config:clang:default
//#Compiler:clang

void _start(void) {}
