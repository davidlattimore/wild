//#AbstractConfig:default
//#EnableLinker:lld
//#DiffIgnore:.dynamic.DT_RELA*
//#DiffIgnore:file-header.entry

//#Config:shared-lib:default
//#LinkArgs:--shared -z now
//#RunEnabled:false

//#Config:no-undefined:default
//#LinkArgs:--shared --no-undefined
//#ExpectError:undefined_strong

//#Config:z-defs:default
//#LinkArgs:-z defs
//#ExpectError:undefined_strong

//#Config:z-undefs:default
//#LinkArgs:-z undefs
//#RunEnabled:false
// GNU ld (2.45) hits an assertion failure for this test
//#SkipArch:loongarch64

//#Config:executable:default
//#CompArgs:-g
//#ExpectError:undefined_strong
//#ExpectError:undefined_symbols.c

int undefined_strong();
__attribute__((weak)) int undefined_weak();

void _start(void) {
  undefined_weak();
  undefined_strong();
}
