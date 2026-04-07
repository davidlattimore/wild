//#Object:dup1.c
//#ExpectError:Duplicate

int foo(void) { return 1; }
int main() { return foo(); }
