//#LinkerDriver:clang
//#ExpectError:undefined

int missing_fn(void);
int main() { return missing_fn(); }
