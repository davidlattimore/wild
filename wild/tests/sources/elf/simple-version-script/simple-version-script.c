// Tests operation with a simple version script. One where we don't define any
// versions and only use the script to control which symbols get exportedd and
// which don't.

//#Object:simple-version-script-1.c
//#CompArgs:-fPIC
//#RunEnabled:false
//#LinkArgs:--shared --version-script=./simple-version-script.map -z now
//#ExpectDynSym:foo
//#ExpectDynSym:bar
//#NoDynSym:aaa1
//#NoDynSym:aaa2
//#DiffIgnore:section.got

#define WEAK __attribute__((weak))

// This symbol has a second, non-weak definition in another file.
void WEAK foo(void) {}

// This symbol is the only definition.
void WEAK bar(void) {}

// These two symbols aren't listed in the version script, so should be matched
// by the local wildcard and downgraded to non-exported.
void WEAK aaa1(void) {}
void aaa2(void) {}
