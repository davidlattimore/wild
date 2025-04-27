// Runtime for when we're not using libc.

// This should be called at the start of _start.
void runtime_init(void);

void exit_syscall(int exit_code);
