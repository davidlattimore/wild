//#RunEnabled:false
//#SkipLinker:ld
//#LinkArgs:-T ./linker-script-defsym-notfound.ld
//#ExpectError:Undefined symbol 'non_existent_symbol'

void _start() {}
