//#AbstractConfig:default
//#RequiresLinkerPlugin:true
//#Compiler:gcc
//#LinkerDriver:gcc
//#CompArgs:-flto -O2 -fPIE
//#Object:runtime.c
//#DiffIgnore:section.got
//#DiffIgnore:dynsym.__bss_start.section
//#DiffIgnore:dynsym._edata.section
//#DiffIgnore:dynsym._end.section
//#DiffIgnore:dynsym.__BSS_END__.section
//#DiffIgnore:dynsym.__DATA_BEGIN__.section
//#DiffIgnore:dynsym.__SDATA_BEGIN__.section
//#DiffIgnore:dynsym.__bss_end__.section
//#DiffIgnore:dynsym._bss_end__.section
//#DiffIgnore:dynsym.__bss_start__.section
//#DiffIgnore:dynsym.__end__.section
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT
//#DiffIgnore:file-header.entry
//#SkipArch:loongarch64

//#Config:archive-export-all:default
//#Archive:lto-export-dynamic-def.c:-flto -O2
//#LinkArgs:-flto -nostdlib -pie -Wl,-z,now,--export-dynamic
//#ExpectDynSym:foo
//#ExpectDynSym:bar
//#ExpectDynSym:protected_export
//#ExpectDynSym:runtime_init
//#ExpectDynSym:exit_syscall
//#NoDynSym:hidden_export

//#Config:archive-export-exact:default
//#Archive:lto-export-dynamic-def.c:-flto -O2
//#LinkArgs:-flto -nostdlib -pie -Wl,-z,now,--export-dynamic-symbol=foo
//#ExpectDynSym:foo
//#NoDynSym:bar
//#NoDynSym:hidden_export
//#NoDynSym:protected_export

//#Config:archive-export-list:default
//#Archive:lto-export-dynamic-def.c:-flto -O2
//#LinkArgs:-flto -nostdlib -pie -Wl,-z,now,--export-dynamic-symbol-list=./lto-export-dynamic.def
//#ExpectDynSym:foo
//#NoDynSym:bar
//#NoDynSym:hidden_export
//#NoDynSym:protected_export

//#Config:object-export-exact:default
//#Object:lto-export-dynamic-def.c:-flto -O2
//#LinkArgs:-flto -nostdlib -pie -Wl,-z,now,--export-dynamic-symbol=foo
//#ExpectDynSym:foo
//#NoDynSym:bar
//#NoDynSym:hidden_export
//#NoDynSym:protected_export

//#Config:shared-default:default
//#CompArgs:-flto -O2 -fPIC
//#Archive:lto-export-dynamic-def.c:-flto -O2 -fPIC
//#LinkArgs:-flto -nostdlib -shared -Wl,-z,now
//#RunEnabled:false
//#SkipArch:ppc64le
//#ExpectDynSym:foo
//#ExpectDynSym:bar
//#ExpectDynSym:protected_export
//#ExpectDynSym:runtime_init
//#ExpectDynSym:exit_syscall
//#NoDynSym:hidden_export

//#Config:shared-version-script:default
//#CompArgs:-flto -O2 -fPIC
//#Archive:lto-export-dynamic-def.c:-flto -O2 -fPIC
//#LinkArgs:-flto -nostdlib -shared -Wl,-z,now,--version-script=./lto-export-dynamic.map
//#RunEnabled:false
//#SkipArch:ppc64le
//#ExpectDynSym:foo
//#NoDynSym:bar
//#NoDynSym:hidden_export
//#NoDynSym:protected_export

//#Config:shared-exclude-archive:default
//#CompArgs:-flto -O2 -fPIC
//#Archive:lto-export-dynamic-def.c:-flto -O2 -fPIC
//#LinkArgs:-flto -nostdlib -shared -Wl,-z,now,--exclude-libs=lto-export-dynamic-def.a
//#RunEnabled:false
//#SkipArch:ppc64le
//#ExpectDynSym:runtime_init
//#ExpectDynSym:exit_syscall
//#NoDynSym:foo
//#NoDynSym:bar
//#NoDynSym:hidden_export
//#NoDynSym:protected_export

//#Config:unreferenced-archive-export:default
//#Archive:lto-export-dynamic-def.c:-flto -O2
//#Archive:lto-export-dynamic-unreferenced.c:-flto -O2
//#LinkArgs:-flto -nostdlib -pie -Wl,-z,now,--export-dynamic-symbol=unreferenced_export
//#NoDynSym:foo
//#NoDynSym:bar
//#NoDynSym:hidden_export
//#NoDynSym:protected_export
//#NoSym:unreferenced_export

#include "../common/runtime.h"

void foo(void);
void bar(void);
void hidden_export(void) __attribute__((visibility("hidden")));
void protected_export(void) __attribute__((visibility("protected")));

void _start(void) {
  runtime_init();
  foo();
  bar();
  hidden_export();
  protected_export();
  exit_syscall(42);
}
