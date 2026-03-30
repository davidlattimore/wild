//#AbstractConfig:default
//#Mode:dynamic
//#RunEnabled:false
//#DiffEnabled:false
//#CompArgs:-fPIC
//#LinkArgs:-shared -z now
//#Archive:hidden-weak-archive-visibility-1.c
//#Object:hidden-weak-archive-visibility-2.c
//#NoDynSym:get_value
//#ExpectDynSym:public_func

//#Config:vacant:default

//#Config:occupied:default
//#Object:hidden-weak-archive-visibility-3.c
//#ExpectDynSym:other_func

__attribute__((weak, visibility("hidden"))) extern int get_value(void);

int public_func(void) {
  if (get_value) {
    return get_value();
  }
  return 0;
}
