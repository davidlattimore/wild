//#LinkerDriver:direct
//
// Same as rust-alloc but uses wild as the direct linker (rustc -Clinker=wild)
// rather than going through clang. This triggers the bug where wild emits
// chained-fixup bind entries for symbols like __rust_alloc that are defined
// internally. The clang driver path masks this because it restructures how
// objects are passed.

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

    // String exercises alloc growth paths
    let s: String = (0..100).map(|i| format!("{i:03}")).collect();
    assert_eq!(s.len(), 300);

    std::process::exit(42);
}
