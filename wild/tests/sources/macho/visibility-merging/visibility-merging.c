//#Object:visibility-merging1.c

// Tests that when two objects define the same symbol with different visibility,
// the more restrictive visibility wins.
// data1: default in this file, hidden in the other → hidden wins.
// data2: stays default → exported.

int data1 __attribute__((weak)) = 0x42;
int data2 __attribute__((weak)) = 42;

int main() { return data2; }
