//#AbstractConfig:default
//#DiffIgnore:section.tdata.alignment
// We include some more archive members than what other linkers do (#162).
//#DiffIgnore:debug_info.missing_unit
//#Cross: false

//#Config:llvm-static:default
//#CompArgs:--target x86_64-unknown-linux-musl -C relocation-model=static -C target-feature=+crt-static -C debuginfo=2
//#Arch: x86_64

//#Config:llvm-static-aarch64:default
//#CompArgs:--target aarch64-unknown-linux-musl -C relocation-model=static -C target-feature=+crt-static -C debuginfo=2
//#Arch: aarch64

//#Config:cranelift-static:default
//#CompArgs:-Zcodegen-backend=cranelift --target x86_64-unknown-linux-musl -C relocation-model=static -C target-feature=+crt-static -C debuginfo=2 --cfg cranelift
//#Arch: x86_64

//#Config:cranelift-static-aarch64:default
//#CompArgs:-Zcodegen-backend=cranelift --target aarch64-unknown-linux-musl -C relocation-model=static -C target-feature=+crt-static -C debuginfo=2 --cfg cranelift
//#Arch: aarch64

//#Config:llvm-dynamic:default
//#CompArgs:-C debuginfo=2
//#DiffIgnore:.dynamic.DT_JMPREL
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:.dynamic.DT_PLTGOT
//#DiffIgnore:.dynamic.DT_PLTREL
//#Cross: true

fn foo() {
    panic!("Make sure unwinding works");
}

fn main() {
    // Make sure panics and catching them work. This relies on .eh_frame being correct. Cranelift
    // doesn't currently support this, so we disable it there.
    if !cfg!(cranelift) && std::panic::catch_unwind(foo).is_ok() {
        std::process::exit(101);
    }

    // Make sure we can canonicalise a path. This was failing at one point due to the incorrect
    // version of a libc function being called. Implementing symbol versioning fixed it.
    let current_dir = match std::fs::canonicalize(".") {
        Ok(p) => p,
        Err(e) => {
            println!("{e}");
            std::process::exit(102);
        }
    };
    if current_dir.components().count() <= 1 {
        std::process::exit(103);
    }

    std::process::exit(42);
}
