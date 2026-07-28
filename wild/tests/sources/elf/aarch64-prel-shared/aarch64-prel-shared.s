// Test that R_AARCH64_PREL32 to a preemptible symbol errors in shared objects.
// lld errors with "cannot be used against symbol; recompile with -fPIC"
// GNU ld silently succeeds on this relocation.
//#Arch:aarch64
//#Mode:dynamic
//#ReferenceLinkers:lld
//#LinkArgs:-shared --no-gc-sections
//#ExpectError:recompile with -fPIC

.globl foo
foo:
    .word 0

.data
    .word foo - .
