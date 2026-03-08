//#Shared:shlib-undefined-3.c
//#LinkArgs:--no-as-needed

int def3(void);

int call_def3(void) { return def3(); }
