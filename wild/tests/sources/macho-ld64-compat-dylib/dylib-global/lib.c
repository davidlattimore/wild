// Dylib exports a writable global. Exercises __DATA emission in
// dylib output and dlsym'd data lookup (vs function lookup).
int counter = 7;
int bump(void) { return ++counter; }
