// Helper for gdb-index test: provides a function in a separate compilation
// unit so that the .gdb_index CU list has multiple entries.

int math_add(int a, int b) { return a + b; }

int math_mul(int a, int b) { return a * b; }
