// Constructors must take no parameters.
//#ExpectError: constructor.*(no parameters|cannot take arguments)

__attribute__((constructor(100))) static int init(int unused) { return 0; }

void _start(void) {}
