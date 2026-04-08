// Tests that a strong definition of main overrides a weak one.
//#Object:weak-entry1.c

__attribute__((weak)) int main() { return 5; }
