//#CompArgs:-fPIC

int g = 7;
int* p = &g;

void _start(void) {
  if (*p != 7) {
    __builtin_trap();
  }
}
