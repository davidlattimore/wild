//#AbstractConfig:default
//#RunEnabled:false
//#DiffIgnore:rel.extra-opt.R_AARCH64_CALL26.ReplaceWithNop.static-non-pie

//#Config:report-all:default
//#LinkArgs:--unresolved-symbols=report-all
//#ExpectError:foo

//#Config:ignore-all:default
//#LinkArgs:--unresolved-symbols=ignore-all

//#Config:ignore-in-object-files:default
//#LinkArgs:--unresolved-symbols=ignore-in-object-files

//#Config:ignore-in-shared-libs:default
//#LinkArgs:--unresolved-symbols=ignore-in-shared-libs
//#ExpectError:foo

//#Config:warn-unresolved-symbols:default
//#LinkArgs:--warn-unresolved-symbols

//#Config:error-unresolved-symbols:default
//#LinkArgs:--error-unresolved-symbols
//#ExpectError:foo

int foo();

void _start(void) { foo(); }
