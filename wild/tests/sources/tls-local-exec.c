//#AbstractConfig:default
//#DiffIgnore:section.data
//#DiffIgnore:section.data.alignment
//#DiffIgnore:section.rodata
//#DiffIgnore:section.rodata.alignment

//#Config:pie:default
//#CompArgs:-fpie
//#LinkArgs:--cc=gcc -Wl,-z,now

__thread long tvar = 1;
__thread int tvar2 = 2;
__thread char tvar3 = 3;

int main() {
  // __builtin_printf ("%ld, %d, %d\n", tvar, tvar2, tvar3);
  return tvar + tvar2 + tvar3 + 36;
}
