//#LinkerScript:linker-script-segment-start.ld
//#RunEnabled:false
//#DiffEnabled:false
//#Mode:dynamic
//#LinkArgs:-shared -z now
//#CompArgs:-fPIC
// Verify that SEGMENT_START("text", 0) defines __executable_start as a symbol.
//#ExpectSym:__executable_start

extern char __executable_start __attribute__((weak));

/* Referenced so the symbol is kept */
void* get_executable_start(void) { return &__executable_start; }
