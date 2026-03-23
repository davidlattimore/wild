//#AbstractConfig:default
//#RunEnabled:false

//#Config:symbol_alias:default
//#LinkArgs:--defsym=bar=foo
//#ExpectSym:bar section=".text"

//#Config:address_alias:default
//#LinkArgs:--defsym=bar=0x12345678
//#ExpectSym:bar address=0x12345678

//#Config:address_expr:default
//#LinkArgs:--defsym=bar=0x1111+0x2222
//#ExpectSym:bar address=0x3333

//#Config:symbol_expr:default
//#LinkArgs:--defsym=bar=0x1111 --defsym=baz=bar+0x2222
//#ExpectSym:baz address=0x3333

//#Config:symbol_expr2:default
//#LinkArgs:--defsym=bar=0x2222 --defsym=baz=-0x1111+bar
//#ExpectSym:baz address=0x1111

//#Config:not_exist:default
//#LinkArgs:--defsym=bar=notexist
//#SkipLinker:ld
//#ExpectError:Symbol 'notexist' referenced by --defsym

int foo(void) { return 0; }

void _start(void) { foo(); }
