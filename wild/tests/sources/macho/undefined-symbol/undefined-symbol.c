//#ExpectError:(?s)(symbol.*foo|foo.*symbol)

int foo(void);

int main() { return foo(); }
