//#AbstractConfig:default

//#Config:shared-lib:default
//#LinkArgs:--shared -z now
//#RunEnabled:false
//#DiffIgnore:.dynamic.DT_RELA*
//#DiffIgnore:file-header.entry

//#Config:no-undefined:default
//#LinkArgs:--shared --no-undefined
//#ExpectError:Undefined symbols:
//#ExpectError:  undefined_strong

//#Config:executable:default
//#ExpectError:Undefined symbols:
//#ExpectError:  undefined_strong

int undefined_strong();
__attribute__((weak)) int undefined_weak();

void _start(void) {
    undefined_weak();
    undefined_strong();
}
