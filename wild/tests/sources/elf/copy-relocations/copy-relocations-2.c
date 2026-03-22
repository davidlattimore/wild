int s1 = 1;

// Because this alias is a weak symbol, any copy relocations produced by
// references to w1 should instead locate the strong symbol `s1` that is at the
// same address and emit a copy relocation for that instead.
__attribute__((weak, alias("s1"))) extern int w1;

int get_w1(void) { return w1; }

int get_s1(void) { return s1; }

// Repeat the same scenario twice more. These are effectively identical in this
// file. The differences are in how they are referenced in the main file.

int s2 = 2;

__attribute__((weak, alias("s2"))) extern int w2;

int get_s2(void) { return s2; }
int get_w2(void) { return w2; }

int s3 = 3;

__attribute__((weak, alias("s3"))) extern int w3;

int get_s3(void) { return s3; }
int get_w3(void) { return w3; }

// An int that has 64-byte alignment. Notably, the size here is smaller than the
// alignment. This is to verify that we correctly handle the alignment when
// performing a copy relocation.
__attribute__((aligned(0x100))) int aligned_int = 700;

int s4 = 4;

__attribute__((weak, alias("s4"))) extern int w4;

int get_s4(void) { return s4; }
int get_w4(void) { return w4; }
