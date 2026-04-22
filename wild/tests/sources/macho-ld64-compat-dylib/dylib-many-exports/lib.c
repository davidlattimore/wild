// Many exports: stresses the exports-trie builder's prefix-compressed
// radix tree. Catches regressions where the trie emission would split
// edges incorrectly or produce wrong ULEB128 child offsets when the
// branching factor grows beyond the tiny cases.
int fn_aaaa(int x) { return x + 1; }
int fn_aaab(int x) { return x + 2; }
int fn_aabc(int x) { return x + 3; }
int fn_abcd(int x) { return x + 4; }
int fn_bbbb(int x) { return x + 5; }
int fn_bbcc(int x) { return x + 6; }
int fn_bcde(int x) { return x + 7; }
int fn_cccc(int x) { return x + 8; }
int fn_ccdd(int x) { return x + 9; }
int fn_cdef(int x) { return x + 10; }
int fn_dddd(int x) { return x + 11; }
int fn_eeee(int x) { return x + 12; }
int global_a = 100;
int global_b = 200;
int global_c = 300;
