//#Archive:lib.a:weak-vars-archive1.c

// Tests that an archive member providing a needed symbol is loaded.
extern int value;
int main() { return value; }
