//#LinkerDriver:clang
//#Ignore:__eh_frame SUBTRACTOR relocations need correct FDE computation

fn inner() -> String {
    let bt = std::backtrace::Backtrace::force_capture();
    format!("{bt}")
}

fn main() {
    let bt = inner();
    if bt.contains("inner") {
        std::process::exit(42);
    }
    std::process::exit(1);
}
