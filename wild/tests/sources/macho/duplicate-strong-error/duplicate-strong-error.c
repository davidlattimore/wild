//#Object:dup1.c
//#ExpectError:duplicate symbol

int foo(void) { return 1; }
int main() { return foo(); }
