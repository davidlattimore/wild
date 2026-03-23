//#Config:default
//#SkipLinker:ld
//#CompArgs:-fPIC
//#RunEnabled:false
//#ExpectError: Symbol foo has undefined version VERSION_XYZ
//#LinkArgs:--shared --version-script=./symbol-versions-script.map -z now

__asm__(".symver foo_impl,foo@VERSION_XYZ");
__asm__(".symver bar_impl,bar@@VERSION_XYZ");

void foo_impl(void) { __builtin_printf("foo\n"); }
void bar_impl(void) { __builtin_printf("bar\n"); }
