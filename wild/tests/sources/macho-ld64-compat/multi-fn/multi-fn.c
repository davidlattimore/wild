// Multiple-function test: exercises LC_FUNCTION_STARTS with more than
// one ULEB128 delta entry. With a single function, the table is a
// trivial single-delta + terminator + padding; two functions force
// the writer to emit a real delta between function addresses.
int square(int x) { return x * x; }
int cube(int x) { return x * x * x; }
int main(void) { return square(2) + cube(3) - 31; }
