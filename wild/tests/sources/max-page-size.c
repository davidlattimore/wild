//#AbstractConfig:default
//#LinkerDriver:gcc
//#RunEnabled:false
//#DiffIgnore:section.data
//#DiffIgnore:section.rodata.alignment

//#Config:64k:default
//#LinkArgs:-Wl,-z,max-page-size=65536 -Wl,-z,now
//#ExpectLoadAlignment:0x10000

//#Config:1m:default
//#LinkArgs:-Wl,-zmax-page-size=0x100000 -Wl,-z,now
//#ExpectLoadAlignment:0x100000

//#Config:2m:default
//#LinkArgs:-Wl,-z,max-page-size=0x200000 -Wl,-z,now
//#ExpectLoadAlignment:0x200000

#include <stdio.h>

int main() {
  printf("aaa\n");

  return 0;
}
