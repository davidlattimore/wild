// export_name produces an export and EXPORTED linking flag.

//#ExpectSection: name
//#ExpectSym: gc_export_rooted
//#DoesNotContain: gc_export_dead_fn

__attribute__((export_name("gc_export_rooted"))) void gc_export_rooted(void) {}

void gc_export_dead_fn(void) {}

void _start(void) {}
