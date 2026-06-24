// Test that R_X86_64_32 cannot be used when making a shared object.
// .long _shared generates R_X86_64_32 which is illegal in shared objects.
// Both GNU ld and lld error: recompile with -fPIC
//#Arch:x86_64
//#LinkArgs:--no-gc-sections -shared
//#ExpectError:recompile with -fPIC
//#ExpectErrorWild:R_X86_64_32.*cannot be used when making a shared object

.data
.long _shared
