//#Mode:dynamic
//#LinkArgs:-shared -z now
//#Object:visibility-merging-1.c
//#RunEnabled:false
//#DiffIgnore:section.got
// TODO: Prevent dynsym export of symbols like these.
//#DiffIgnore:dynsym.data1.*
//#DiffIgnore:dynsym.data4.*

// This symbol is included, but isn't exported as a dynamic symbol because of a
// second definition in our other file that's marked as hidden.
int data1 __attribute__((weak)) = 0x42;

// This symbol is exported.
int data2 __attribute__((weak)) = 0x88888888;

// This symbol is exported, but is protected, since the definition in the second
// file is.
int data3 __attribute__((weak)) = 0x55;

// Protected here and hidden in our second object. Hidden should take priority.
int data4 __attribute__((weak, visibility(("protected")))) = 0x99;

// Make sure that direct references to `data1` work on account of it being
// hidden.
int get_data1(void) { return data1; }

// Note, we don't check direct references to `data2` and `data3`. In the case of
// `data2`, direct references wouldn't be permitted, since the symbol is
// interposable. In the case of `data3`, the symbol will be protected, so direct
// references should be permitted, however GNU ld < 2.40 would error in the case
// of direct references to protected symbols, so in order to allow our tests to
// pass with such versions, we don't.
