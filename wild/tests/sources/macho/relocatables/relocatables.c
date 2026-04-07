//#Object:relocatables1.c
//#Object:relocatables2.c
//#Ignore:partial linking (-r) not yet implemented for Mach-O

// Tests -r (partial link / relocatable output).
// Link relocatables1.c and relocatables2.c into a single .o via -r,
// then link that combined .o into the final executable.

int add(int, int);
int multiply(int, int);

int main() { return add(30, 12) == 42 && multiply(6, 7) == 42 ? 42 : 1; }
