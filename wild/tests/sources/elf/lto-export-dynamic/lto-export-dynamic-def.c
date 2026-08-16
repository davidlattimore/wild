void foo(void) {}
void bar(void) {}
void hidden_export(void) __attribute__((visibility("hidden")));
void protected_export(void) __attribute__((visibility("protected")));

void hidden_export(void) {}
void protected_export(void) {}
