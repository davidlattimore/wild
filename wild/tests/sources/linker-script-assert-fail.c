//#LinkArgs:-T ./linker-script-assert-fail.ld
//#RunEnabled:false
//#DiffEnabled:false
//#SkipLinker:ld
//#ExpectError:assertion failed: text section cannot be empty
void _start() {}
