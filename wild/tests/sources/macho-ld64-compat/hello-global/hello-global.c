// Second comparison test: exercises __DATA emission. A global
// variable forces wild to produce at least one data section.
int global_counter = 42;
int main(void) { return global_counter; }
