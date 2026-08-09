//#AbstractConfig:base
//#Object:gc-sections2.c
//#Object:gc-sections3.c
//#ExpectSection: name
//#Contains: gc_keep_called_fn

//#Config:default-gc:base
//#DoesNotContain: gc_dead_unreferenced_fn

//#Config:no-gc-sections:base
//#LinkArgs: --no-gc-sections
//#Contains: gc_dead_unreferenced_fn

void gc_keep_called_fn(void);

void _start(void) { gc_keep_called_fn(); }
