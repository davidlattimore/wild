//#Object:custom-section1.c

// Tests that data placed in custom sections via __attribute__((section))
// is correctly linked and accessible at runtime.

extern int get_custom_value(void);

static int my_data __attribute__((used, section("__DATA,__custom"))) = 30;

int main() { return my_data + get_custom_value(); }
