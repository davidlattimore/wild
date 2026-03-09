//#RunEnabled:false
//#SkipLinker:ld
//#LinkArgs:-T ./linker-script-unclosed-comment.ld
//#ExpectError:unclosed comment
void _start() {}
