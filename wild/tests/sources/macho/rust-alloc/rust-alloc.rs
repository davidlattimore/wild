//#LinkerDriver:clang

// Exercises heap allocation to verify that __rust_alloc and related
// allocator symbols are resolved as internal definitions rather than
// chained-fixup imports.  When the linker incorrectly emits bind
// entries for these symbols, dyld fails at launch with:
//   "Symbol not found: __RNvCs…_7___rustc12___rust_alloc"
//
// NOTE: This bug only manifests when wild is the direct linker
// (rustc -Clinker=wild), not when going through clang
// (rustc -Clinker=clang -Clink-arg=-fuse-ld=wild).
// See also: rust-alloc-direct test.

fn main() {
    // Box exercises __rust_alloc + __rust_dealloc
    let b = Box::new(42u64);
    assert_eq!(*b, 42);

    // Vec exercises __rust_alloc + __rust_realloc + __rust_dealloc
    let mut v: Vec<u32> = Vec::new();
    for i in 0..256 {
        v.push(i);
    }
    assert_eq!(v.len(), 256);
    assert_eq!(v[255], 255);

    // String exercises __rust_alloc_zeroed (via Vec<u8> growth)
    let s: String = (0..100).map(|i| format!("{i:03}")).collect();
    assert_eq!(s.len(), 300);

    // HashMap exercises multiple alloc paths
    let mut map = std::collections::HashMap::new();
    for i in 0..64u32 {
        map.insert(i, i * i);
    }
    assert_eq!(map[&7], 49);

    std::process::exit(42);
}
