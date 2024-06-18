__thread int tvar3 = 80;

extern __thread int tvar2;

static __thread int tvar_local = 8;

void set_tvar2(int v) {
    tvar2 = v;
}

void set_tvar3(int v) {
    tvar3 = v;
}

void set_tvar_local(int v) {
    tvar_local = v;
}

int get_tvar_local(void) {
    return tvar_local;
}
