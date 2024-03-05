// This test just makes sure that we can complete the libc startup and shutdown successfully.

//#LinkArgs:static:--cc=clang -static
//#LinkArgs:static-pie:--cc=clang -static-pie

int main() {
    return 42;
}
