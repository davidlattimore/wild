//#Config:default
//#Object:ptr_black_box.c
//#SkipArch:ppc64le
//#LinkerDriver:gcc
//#LinkArgs:-Wl,-znow -pie
//#ReferenceLinkers:lld
//#DiffIgnore:section.rodata
//#DiffIgnore:section.got.plt.entsize
//#DiffIgnore:section.gnu.version_r.alignment

#include "../common/ptr_black_box.h"

__thread unsigned char tls_value = 42;
__thread unsigned char tls_zero[17] __attribute__((aligned(4096)));
unsigned long normal_data = 0x1122334455667788UL;

int main(void) {
  if (ptr_to_int(tls_zero) % 4096 != 0) {
    return 1;
  }
  if (tls_value != 42) {
    return 2;
  }
  if (tls_zero[0] != 0) {
    return 3;
  }
  if (tls_zero[16] != 0) {
    return 4;
  }
  if (normal_data != 0x1122334455667788UL) {
    return 5;
  }

  tls_zero[0] = 10;
  tls_zero[16] = 20;
  return tls_value + tls_zero[0] - tls_zero[16] + 10;
}
