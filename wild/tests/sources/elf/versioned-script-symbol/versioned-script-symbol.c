//#CompArgs:-fPIC
//#RunEnabled:false
// GNU ld discards foo. Wild, like lld doesn't.
//#ReferenceLinkers:lld
//#LinkArgs:--shared -znow ./versioned-script-symbol.map
//#ExpectSym:mysql_affected_rows@libmysqlclient_18
//#DiffIgnore:section.got
//#DiffIgnore:section.gnu.version_d.alignment
//#DiffIgnore:version_d.verdef_1
// TODO: Look into this. Neither GNU ld nor lld emit this dynsym.
//#DiffIgnore:dynsym.mysql_affected_rows.section

int foo(void) { return 42; }
