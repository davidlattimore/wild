//#CompArgs:default:--target x86_64-unknown-linux-musl -C relocation-model=static -C target-feature=+crt-static -C debuginfo=2
//#CompArgs:cranelift:-Zcodegen-backend=cranelift --target x86_64-unknown-linux-musl -C relocation-model=static -C target-feature=+crt-static -C debuginfo=2
//#LinkArgs:static:--cc=clang -static

fn main() {
    std::process::exit(42);
}
