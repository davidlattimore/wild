//#Mode:static
//#Shared:force-dynamic-linking.c
//#ExpectError:(?i-u)Attempted static link of dynamic object

int main() { return 42; }
