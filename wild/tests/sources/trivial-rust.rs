//#CompArgs:default:
//#CompArgs:cranelift:-Zcodegen-backend=cranelift
//#LinkArgs:static:--cc=clang -static

fn main() {
    std::process::exit(42);
}
