// Tests that __cstring literals are accessible and correctly merged.
#include <string.h>

int main() {
  const char* a = "hello";
  const char* b = "world";
  return (strlen(a) == 5 && strlen(b) == 5) ? 42 : 1;
}
