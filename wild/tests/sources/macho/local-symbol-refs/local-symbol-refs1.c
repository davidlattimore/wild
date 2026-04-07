static int other_val = 42;
int* get_local_ptr(void) { return &other_val; }
