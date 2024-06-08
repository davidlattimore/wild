//#AbstractConfig:default
//#DiffIgnore:asm.dummy

//#Config:llvm-static:default
//#CompArgs:--target x86_64-unknown-linux-musl -C relocation-model=static -C target-feature=+crt-static -C debuginfo=2
//#LinkArgs:static:--cc=clang -static

//#Config:cranelift-static:default
//#CompArgs:-Zcodegen-backend=cranelift --target x86_64-unknown-linux-musl -C relocation-model=static -C target-feature=+crt-static -C debuginfo=2 --cfg cranelift
//#LinkArgs:static:--cc=clang -static

//#Config:llvm-dynamic:default
//#CompArgs:-C debuginfo=2
//#LinkArgs:static:--cc=clang
//#DiffIgnore:.dynamic.DT_JMPREL
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:.dynamic.DT_PLTGOT
//#DiffIgnore:.dynamic.DT_PLTREL

fn foo() {
    panic!("Make sure unwinding works");
}

fn main() {
    // Make sure panics and catching them work. This relies on .eh_frame being correct. Cranelift
    // doesn't currently support this, so we disable it there.
    if !cfg!(cranelift) && std::panic::catch_unwind(foo).is_ok() {
        std::process::exit(101);
    }

    // Make sure we can canonicalise a path. This was failing at one point.
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
