int values[4] = {10, 20, 30, 40};

static int return_42(void) { return 42; }

// Function pointer in the data section — requires rebase fixup.
static int (*fn_ptr)(void) = return_42;

int (*get_fn(void))(void) { return fn_ptr; }
