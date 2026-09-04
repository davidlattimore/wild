//#Arch:x86_64
//#Compiler:clang
//#CompArgs:-Xassembler --crel -Xassembler --allow-experimental-crel
//#RequiresCompilerFlags:-Xassembler --crel -Xassembler --allow-experimental-crel
//#LinkArgs:-r
//#ReferenceLinkers:
//#ExpectErrorWild:CREL with partial linking isn't yet supported

.data
.quad undefined_symbol
