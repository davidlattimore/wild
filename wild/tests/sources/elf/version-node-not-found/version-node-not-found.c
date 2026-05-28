//#CompArgs:-fPIC
//#RunEnabled:false
//#SkipLinker:ld
//#Arch:x86_64
//#LinkArgs:--shared ./version-node-not-found.map
//#ExpectError:Symbol mysql_affected_rows has undefined version libmysqlclient_18

int foo(void) { return 42; }
