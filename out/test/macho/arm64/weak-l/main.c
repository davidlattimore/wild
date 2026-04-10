#include <stdio.h>
void hello() __attribute__((weak_import));
int main() {
  if (hello) hello();
  else printf("hello is missing\n");
}
