// Part 1 of the two-object test (paired with b.c). Cross-TU linkage
// exercises the linker's merging of separate .o symtabs, strtabs,
// and compact-unwind sections — a single-.o test can't catch bugs
// where wild emits content that duplicates or reorders when inputs
// are split.
extern int add_one(int);
int main(void) { return add_one(41) - 42; }
