//#Archive:archive_lto.c:-flto
//#Object:runtime.c
//#LinkerDriver:gcc
//#SkipLinker:ld
//#ExpectError:undefined reference to `addition` found in LTO section of archive_lto

extern int addition(int, int);

int main(int argc, char **argv) {
  int a = 1;
  int b = 1;
  int result = addition(a, b);

  return 0;
}
