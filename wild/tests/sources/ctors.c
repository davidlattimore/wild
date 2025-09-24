//#LinkerDriver:gcc
//#DiffIgnore:section.data
//#DiffIgnore:section.rodata

static int ctors_init_val = 0;

void init1() { ctors_init_val += 10; }
__attribute__((section(".ctors"), used)) static void* init1_ptr = init1;

void init2() { ctors_init_val += 30; }
__attribute__((section(".ctors"), used)) static void* init2_ptr = init2;

void init3() { ctors_init_val += 2; }
__attribute__((section(".ctors"), used)) static void* init3_ptr = init3;

int main() {
  if (ctors_init_val != 42) {
    return 123;
  }

  return 42;
}
