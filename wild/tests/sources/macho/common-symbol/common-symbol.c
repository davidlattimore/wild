//#Object:common-symbol1.c

// Test that tentative (common) definitions from multiple objects merge
// correctly.
int shared_var;
int main() { return shared_var == 0 ? 42 : 1; }
