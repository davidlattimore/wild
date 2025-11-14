//#AbstractConfig:default
//#RunEnabled:false

//#Config:symbol_alias:default
//#LinkArgs:--defsym=bar=foo
//#ExpectSym:bar section=".text"

//#Config:address_alias:default
//#LinkArgs:--defsym=bar=0x12345678
//#ExpectSym:bar address=0x12345678

int foo(void) { return 0; }

void _start(void) { foo(); }
