int foo[8] = {0, 1, 2, 3, 4, 5, 6, 7};
int bar[8] = {0x0, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70};

int check_pointers(int **p) {
    if (*p[0] != 2) {
        return *p[0];
    }

    if (*p[1] != 0x60) {
        return *p[1];
    }
    
    return 42;
}
