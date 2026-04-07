//#Object:string-merging1.c
//#Contains:Hello Wild

extern const char* get_str1(void);
const char* get_str2(void) { return "Hello Wild"; }
int main() {
  const char* a = get_str1();
  const char* b = get_str2();
  if (a[0] != 'H') return 1;
  if (b[0] != 'H') return 2;
  // String merging is optional — just verify both are correct.
  return 42;
}
