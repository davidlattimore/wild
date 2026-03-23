typedef void (*Func)(void);

extern void foo(void);
extern void bar(void);

Func get_foo(void) { return foo; }
Func get_bar(void) { return bar; }
