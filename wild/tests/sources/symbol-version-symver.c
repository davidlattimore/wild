//#Config:default
//#DiffIgnore:.dynamic.DT_RELAENT
//#DiffIgnore:.dynamic.DT_RELA
//#RunEnabled:false
//#LinkArgs:--shared --version-script=./symbol-versions-script.map -z now

__asm__(".symver foo_impl,foo@VER_1.0");
__asm__(".symver bar_impl,bar@@VER_1.0");

void foo_impl(void) { __builtin_printf("foo\n"); }
void bar_impl(void) { __builtin_printf("bar\n"); }
