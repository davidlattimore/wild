//#DiffIgnore:asm.__udivti3
//#DiffIgnore:.dynamic.*
// It looks like GNU ld sets .tdata's alignment to match .tbss's alignment
//#DiffIgnore:section.tdata.alignment
//#CompArgs:-C debuginfo=2
//#Shared:rdyn1.rs

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
