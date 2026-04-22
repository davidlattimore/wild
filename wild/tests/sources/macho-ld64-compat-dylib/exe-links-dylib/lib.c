// Dylib: provides a function that the exe (also wild-built) links
// against directly (not via dlopen). Exercises the wild→wild
// exe→dylib link path — the exe's chained fixups must resolve
// through a LC_LOAD_DYLIB entry pointing at this dylib.
int answer(void) { return 42; }
