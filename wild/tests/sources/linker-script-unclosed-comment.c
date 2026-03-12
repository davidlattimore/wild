//#RunEnabled:false
//#SkipLinker:ld
//#LinkArgs:-T ./linker-script-unclosed-comment.ld
//#ExpectError:Unclosed comment
void _start() {}
