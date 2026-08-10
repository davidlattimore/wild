//#Config:no-option
//#ExpectSym: memory
//#ExpectSym: _start

//#Config:default-value
//#LinkArgs: --export-memory
//#ExpectSym: memory
//#ExpectSym: _start

//#Config:custom-name
//#LinkArgs: --export-memory=foo
//#ExpectSym: foo
//#ExpectSym: _start
//#NoSym: memory

void _start(void) {}
