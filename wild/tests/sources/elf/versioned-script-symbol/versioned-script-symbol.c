//#CompArgs:-fPIC
//#RunEnabled:false
//#LinkArgs:--shared -znow ./versioned-script-symbol.map
//#ExpectSym:mysql_affected_rows@libmysqlclient_18
//#DiffIgnore:section.got

int foo(void) { return 42; }
