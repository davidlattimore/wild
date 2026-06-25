//#RunEnabled:false
//#ReferenceLinkers:
//#LinkArgs:-T ./linker-script-defsym-notfound.ld
//#ExpectError:Symbol 'non_existent_symbol' referenced by linker script does not exist

void _start() {}
