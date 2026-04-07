//#ExpectError:undefined
//#Ignore:needs .tbd symbol parsing to distinguish undefined from dynamic imports

int missing_fn(void);
int main() { return missing_fn(); }
