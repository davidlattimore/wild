//#TestUpdateInPlace:true
//#LinkerDriver:clang
//#ExpectWarningWild:Fat object file is not supported yet
//#DiffIgnore:section.__unwind_info

#include <stdio.h>
#include <string.h>

int value = 121;

int main() {
  char buf[128];
  sprintf(buf, "Hello %s: %d", "world", value);
  printf("buf: '%s'\n", buf);

  unsigned char csum = 0;
  for (int i = 0; i < strlen(buf); ++i) {
    csum += buf[i];
  }
  return csum;
}
