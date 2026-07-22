//#LinkerDriver:gcc
//#SkipArch:ppc64le
//#DiffIgnore:section.rodata
//#DiffIgnore:section.data

static __thread volatile unsigned char tls_zeros[0x22000];

int main(void) {
  if (tls_zeros[0] != 0 || tls_zeros[sizeof(tls_zeros) - 1] != 0) {
    return 2;
  }
  return 42;
}
