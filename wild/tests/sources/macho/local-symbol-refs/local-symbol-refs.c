//#Object:local-symbol-refs1.c

static int local_val = 42;
int* get_local_ptr(void);
int main() { return *get_local_ptr() == local_val ? local_val : 1; }
