//#AbstractConfig:default
//#RequiresGlibc:true
//#CompArgs:-fno-pie
//#Mode:dynamic
//#Object:runtime.c
//#Object:canonical-plt-pic.c:-fPIC
//#ReferenceLinkers:bfd,lld
//#Shared:canonical-plt-shared.c:-fPIC
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:.dynamic.DT_RELA*

//#Config:x86_64:default
//#Arch:x86_64
//#ExpectDynSym:called_only address=0
//#ExpectDynSym:called_ifunc_only address=0,type=func
//#ExpectDynSym:imported_ifunc type=func

//#Config:other:default
//#Arch:riscv64,loongarch64

//#Config:aarch64:default
//#Arch:aarch64
//#DiffMatchAny:true

#include "../common/runtime.h"

typedef void (*Func)(void);

extern void foo(void);
extern void called_only(void);
extern void called_ifunc_only(void);
extern Func get_foo(void);
extern Func get_foo_from_executable(void);
extern Func get_imported_ifunc_from_executable(void);
extern void imported_ifunc(void);

void _start(void) {
  runtime_init();

  Func executable_address = foo;
  Func shared_object_address = get_foo();
  Func executable_pic_address = get_foo_from_executable();
  Func imported_ifunc_address = imported_ifunc;

  if (executable_address != shared_object_address) {
    exit_syscall(100);
  }

  if (executable_address != executable_pic_address) {
    exit_syscall(101);
  }

  if (imported_ifunc_address != get_imported_ifunc_from_executable()) {
    exit_syscall(102);
  }

  executable_address();
  shared_object_address();
  executable_pic_address();
  imported_ifunc_address();
  called_only();
  called_ifunc_only();

  exit_syscall(42);
}
