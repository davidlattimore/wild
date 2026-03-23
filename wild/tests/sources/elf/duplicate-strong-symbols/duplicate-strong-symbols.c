//#Config:dup
//#SkipLinker:ld
//#Object:duplicate_strong_symbols2.c
//#ExpectError:Duplicate symbols

//#Config:allow-multiple-definition
//#RunEnabled:false
//#Object:duplicate_strong_symbols2.c
//#LinkArgs:--allow-multiple-definition

//#Config:z-muldefs
//#RunEnabled:false
//#Object:duplicate_strong_symbols2.c
//#LinkArgs:-z muldefs

//#Config:dup-lto
//#RequiresLinkerPlugin:true
//#Compiler:clang
//#LinkerDriver:clang
//#LinkArgs:-nostdlib -Wl,-znow -flto
//#SkipLinker:ld
//#Object:duplicate_strong_symbols2.c:-flto
//#ExpectError:Duplicate symbols

int test_func(void) { return 0; }

void _start(void) { test_func(); }
