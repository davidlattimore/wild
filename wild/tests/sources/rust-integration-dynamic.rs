//#DiffIgnore:asm.*
//#DiffIgnore:.dynamic.*
//#CompArgs:default:-C debuginfo=2
//#LinkArgs:dynamic:--cc=clang
//#InputType:Shared

extern {
    fn foo() -> i32;
    fn bar() -> i32;
    fn get_tls1() -> i32;
    fn set_tls1(value: i32);
}

fn main() {
    if unsafe { foo() } != 10 {
        std::process::exit(100);
    }

    if unsafe { bar() } != 18 {
        std::process::exit(101);
    }

    unsafe { set_tls1(88); }
    if unsafe { get_tls1() } != 88 {
        std::process::exit(102);
    }

    std::process::exit(42);
}
