typedef void (*Func)(void);

void foo(void) {}
void called_only(void) {}

static void imported_ifunc_impl(void) {}
static Func imported_ifunc_resolver(void) { return imported_ifunc_impl; }
__attribute__((ifunc("imported_ifunc_resolver"))) void imported_ifunc(void);

static void called_ifunc_only_impl(void) {}
static Func called_ifunc_only_resolver(void) { return called_ifunc_only_impl; }
__attribute__((ifunc("called_ifunc_only_resolver"))) void called_ifunc_only(void);

Func get_foo(void) { return foo; }
