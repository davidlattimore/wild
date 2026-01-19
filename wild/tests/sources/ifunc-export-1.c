typedef void (*Func)(void);

extern void foo(void);

Func get_foo(void) { return foo; }
