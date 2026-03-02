typedef void (*Func)(void);

// IFunc definitions live here, in the -fPIC object. That means the only
// references to foo/bar from text in this file go through the GOT
// (R_X86_64_REX_GOTPCRELX), so the resolved function address is the
// canonical one. The linker must resolve the data pointers below via
// IRELATIVE so they match the GOT-resolved address.

static void real_foo(void) {}
static void real_bar(void) {}

__attribute__((ifunc("resolve_foo"))) void foo(void);
static Func resolve_foo(void) { return real_foo; }

__attribute__((ifunc("resolve_bar"))) void bar(void);
static Func resolve_bar(void) { return real_bar; }

// Global data pointers initialised to ifunc addresses. The compiler emits
// R_X86_64_64 relocations for these when compiled with -fPIC. In a static
// non-PIE executable the linker must resolve them via IRELATIVE entries in
// .rela.plt so that they hold the same address as what the GOT resolves to.
Func foo_data_ptr = foo;
Func bar_data_ptr = bar;

// Return the ifunc address via a GOT-relative load (GOTPCRELX).
Func get_foo(void) { return foo; }
Func get_bar(void) { return bar; }