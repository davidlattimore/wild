__thread int tvar3 = 80;

extern __thread int tvar2;

void set_tvar2(int v) {
    tvar2 = v;
}
