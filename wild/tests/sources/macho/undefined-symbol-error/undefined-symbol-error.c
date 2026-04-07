//#ExpectError:undefined
//#Ignore:undefined symbol errors not yet reported for Mach-O

int missing_fn(void);
int main() { return missing_fn(); }
