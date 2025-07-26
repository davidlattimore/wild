//#AbstractConfig:default

//#Config:shared-lib:default
//#LinkArgs:--shared -z now
//#RunEnabled:false
//#DiffIgnore:.dynamic.DT_RELA*
//#DiffIgnore:file-header.entry

//#Config:no-undefined:default
//#LinkArgs:--shared --no-undefined
//#ExpectError:  undefined_strong

//#Config:executable:default
//#CompArgs:-g
//#ExpectError:  undefined_strong
//#ExpectError:undefined_symbols.c

//#Config:report-all:default
//#LinkArgs:--unresolved-symbols=report-all
//#ExpectError: undefined_strong

//#Config:ignore-in-shared-libs:default
//#LinkArgs:--unresolved-symbols=ignore-in-shared-libs
//#ExpectError: undefined_strong

//#Config:ignore-in-shared-libs2:default
//#SkipLinker:ld
//#DiffEnabled:false
//#RunEnabled:false
//#LinkArgs:--shared --unresolved-symbols=ignore-in-object-files
//#ExpectError: undefined_strong

//#Config:ignore-in-object-files:default
//#SkipLinker:ld
//#DiffEnabled:false
//#RunEnabled:false
//#LinkArgs:--unresolved-symbols=ignore-in-object-files

//#Config:ignore-in-object-files2:default
//#SkipLinker:ld
//#DiffEnabled:false
//#RunEnabled:false
//#LinkArgs:--unresolved-symbols=ignore-in-shared-libs
//#ExpectError: undefined_strong

int undefined_strong();
__attribute__((weak)) int undefined_weak();

void _start(void) {
    undefined_weak();
    undefined_strong();
}
