//#AbstractConfig:default
//#LinkerDriver:gcc
// -gdwarf-4 forces .debug_line v4 — wild's elf_line_v5 pass only
// upgrades v4. Modern gcc/clang default to DWARF 5 which would
// skip the upgrade entirely and the -O1 config below couldn't
// assert that .debug_line_str was created.
//#CompArgs:-g -gdwarf-4 -O0
//#LinkArgs:-Wl,--compress-debug-sections=zstd
//#SkipLinker:ld
//#SkipLinker:lld
//#DiffEnabled:false
//#ExpectCompressedSection:.debug_info
// At least 1 text symbol must resolve to function/file/line via DWARF.
// Tiny fixtures may only have `main` resolvable; lower bound stays loose.
//#ExpectDwarfResolves:1

//#Config:gcc:default

//#Config:clang:default
//#Compiler:clang

// Combined -O1 path: line v5 upgrade + zstd compression.
//
// Asserts the compress pass (universally applied). The line v5
// upgrade tries to run here too but skips gracefully because this
// fixture is too small for path pooling to save more bytes than
// the v5 format overhead costs. On real-world workloads
// (substrate-class, thousands of CUs sharing workspace paths) the
// rewrite saves ~16 % of .debug_line — proven separately in
// experiments/debug-line-rewrite on midnight-node.
//#Config:opt1:default
//#LinkArgs:-Wl,-O1
//#ExpectCompressedSection:.debug_info
//#ExpectDwarfResolves:1

// Enough structs + functions + string literals to ensure the
// compiler emits a >256-byte .debug_info (wild's MIN_COMPRESSIBLE
// threshold in elf_compress.rs). `.debug_str` + `.debug_line` may
// or may not clear the threshold on tiny programs depending on
// toolchain, so we only hard-assert `.debug_info`.
//
// Linker-diff is disabled because older binutils on CI hosts may
// not know --compress-debug-sections=zstd; the SHF_COMPRESSED
// check in ExpectCompressedSection is the assertion that matters.

#include <stdio.h>

struct point { int x, y, z; const char *tag; };
struct range { int lo, hi; double scale; };
struct config {
    const char *name;
    int values[8];
    struct point origin;
    struct range bounds;
};

static const char *messages[] = {
    "entry zero: wild linker debug-info padding text one",
    "entry one:  deliberately long so .debug_str grows",
    "entry two:  third message to pad the merged-string table",
    "entry three: fourth",
    "entry four: fifth",
    "entry five: sixth",
    "entry six: seventh line",
    "entry seven: eighth and final",
};

static int compute_point(struct point *p, int seed) {
    p->x = seed;
    p->y = seed + 1;
    p->z = seed + 2;
    p->tag = messages[seed & 7];
    return p->x + p->y + p->z;
}

static int compute_range(struct range *r, int lo, int hi) {
    r->lo = lo;
    r->hi = hi;
    r->scale = (double)(hi - lo) / 2.0;
    return r->hi - r->lo;
}

static int configure(struct config *c, int seed) {
    c->name = messages[seed & 7];
    for (int i = 0; i < 8; i++) {
        c->values[i] = seed + i * 3;
    }
    compute_point(&c->origin, seed);
    compute_range(&c->bounds, seed, seed + 100);
    return c->values[0] + c->origin.x + c->bounds.lo;
}

int main(void) {
    struct config cfg;
    int sum = 0;
    for (int i = 0; i < 4; i++) {
        sum += configure(&cfg, i);
    }
    // wild's run-binary check expects exit code 42 (the magic number
    // its other test fixtures use).
    return 42 + (sum & 0);
}
