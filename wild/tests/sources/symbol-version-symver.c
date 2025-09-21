//#AbstractConfig:default

//#Config:shared-lib:default
//#SkipLinker:ld
//#RunEnabled:false
//#LinkArgs:--shared --version-script=./symbol-versions-script.map
//#ExpectError: symbol version definition

__asm__(".symver foo,xyz@VER_1");
__asm__(".symver bar,xyz@@VER_2");

void foo(void) { __builtin_printf("foo\n"); }
void bar(void) { __builtin_printf("bar\n"); }
