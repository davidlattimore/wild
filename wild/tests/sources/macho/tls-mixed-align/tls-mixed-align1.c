// An int in __thread_data forces tdata.align = 4. Nothing else in
// tdata, so the layout engine can't accidentally bump tdata's
// alignment to 16 via some other variable.
__thread int tdata_small = 7;

// A 16-byte aligned array in __thread_bss. The attribute is load-
// bearing — without it clang gives natural (8-byte) alignment.
__thread long long tbss_wide[2] __attribute__((aligned(16)));
