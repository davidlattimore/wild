extern _Thread_local int global_tls1;

int bar() { return global_tls1; }
