//#DiffIgnore:.dynamic.*
// It looks like GNU ld sets .tdata's alignment to match .tbss's alignment
//#DiffIgnore:section.tdata.alignment
//#CompArgs:-C debuginfo=2
//#Shared:rdyn1.rs
//#Cross: false

extern "C" {
    fn foo() -> i32;
    fn bar() -> i32;
    fn get_tls1() -> i32;
    fn set_tls1(value: i32);
    fn get_tls2() -> i32;
    fn set_tls2(value: i32);
}

fn main() {
    if unsafe { foo() } != 10 {
        std::process::exit(100);
    }

    if unsafe { bar() } != 18 {
        std::process::exit(101);
    }

    if unsafe { get_tls1() } != 1 {
        std::process::exit(102);
    }
    if unsafe { get_tls2() } != 2 {
        std::process::exit(103);
    }

    unsafe {
        set_tls1(88);
    }
    unsafe {
        set_tls2(55);
    }

    if unsafe { get_tls1() } != 88 {
        std::process::exit(104);
    }
    if unsafe { get_tls2() } != 55 {
        std::process::exit(105);
    }

    std::process::exit(42);
}
