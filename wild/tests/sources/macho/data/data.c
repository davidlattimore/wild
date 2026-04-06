static char data1[] = "Hello";
char data2[] = "World";

int main() {
  if (data1[0] != 'H') return 1;
  if (data2[0] != 'W') return 2;
  return 42;
}
