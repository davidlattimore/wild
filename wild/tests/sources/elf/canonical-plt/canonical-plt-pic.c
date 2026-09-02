typedef void (*Func)(void);

extern void foo(void);
extern void imported_ifunc(void);

Func get_foo_from_executable(void) { return foo; }
Func get_imported_ifunc_from_executable(void) { return imported_ifunc; }
