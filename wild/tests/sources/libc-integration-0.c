//#OverrideCompArgs:-ftls-model=global-dynamic

__thread int tvar3 = 80;

extern __thread int tvar2;

void set_tvar2(int v) {
    tvar2 = v;
}
