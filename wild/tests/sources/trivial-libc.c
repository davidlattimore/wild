// This test just makes sure that we can complete the libc startup and shutdown successfully.

//#LinkArgs:clang-static:--cc=clang -static
//#LinkArgs:clang-static-pie:--cc=clang -static-pie
//#LinkArgs:gcc-static:--cc=gcc -static
//#LinkArgs:gcc-static-pie:--cc=gcc -static-pie

int main() {
    return 42;
}
