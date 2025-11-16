//#Config:wip
//#LinkerDriver:gcc
//#LinkArgs:-Wl,-z,now,-no-pie
//#DiffIgnore:section.rodata

__thread int tvar __attribute__((common));

int main() {
  tvar += 41;
  return ++tvar;
}
