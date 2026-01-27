//#Config:shared
//#Object:runtime.c
//#LinkArgs:-shared -f foo --auxiliary bar -z now
//#DiffIgnore:section.got
//#RunEnabled:false

//#Config:no-shared
//#Object:runtime.c
//#LinkArgs:-f foo --auxiliary bar
//#ExpectError:-f may not be used without -shared
