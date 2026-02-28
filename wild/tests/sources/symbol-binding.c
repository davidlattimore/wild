//#Object:runtime.c
//#DiffEnabled:false
//#Mode:unspecified
//#LinkArgs:-z now -as-needed
//#SkipLinker:ld
//#Shared:symbol-binding-dyn.c
//#Object:symbol-binding-weak.c
//#Archive:symbol-binding-strong.c

#include "runtime.h"

// Test that get_non_dynamic correctly selects the strong definition over the
// weak one when the primary definition is from a shared object.
//
// The hidden visibility on the declarations below forces allow_dynamic=false
// when resolving these symbols, which triggers the get_non_dynamic code path.
//
// symbol-binding-strong.c is linked as an archive, so it will only be loaded if
// get_non_dynamic returns its symbol. With the old (broken) get_non_dynamic that
// just picks the first non-dynamic alternative, the weak definition from
// symbol-binding-weak.c (an always-loaded object) would be picked, the archive
// would never be loaded, and select_symbol would see the strong definition as
// Undefined. The fix makes get_non_dynamic consider symbol binding priority,
// so it picks the strong archive member, causing it to be loaded.

__attribute__((visibility("hidden"))) int foo(void);
__attribute__((visibility("hidden"))) int bar(void);

void _start(void) {
  runtime_init();

  // foo is defined weakly in symbol-binding-weak.c (returns 1) and strongly in
  // symbol-binding-strong.c (returns 2). The strong archive definition should
  // win because get_non_dynamic should prefer it and trigger its loading.
  if (foo() != 2) {
    exit_syscall(foo());
  }

  // bar is defined strongly in symbol-binding-weak.c (returns 10) and weakly in
  // symbol-binding-strong.c (returns 20). The always-loaded strong definition
  // should win regardless.
  if (bar() != 10) {
    exit_syscall(bar());
  }

  exit_syscall(42);
}
