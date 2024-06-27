use std::cell::Cell;

#[no_mangle]
pub extern fn foo() -> i32 {
    10
}

#[no_mangle]
pub extern fn bar() -> i32 {
    18
}


thread_local! {
    pub static TLS1: Cell<i32> = const { Cell::new(1) };
}

thread_local! {
    pub static TLS2: Cell<i32> = const { Cell::new(2) };
}

#[no_mangle]
pub extern fn get_tls1() -> i32 {
    TLS1.get()
}

#[no_mangle]
pub extern fn set_tls1(value: i32) {
    TLS1.set(value);
}

#[no_mangle]
pub extern fn get_tls2() -> i32 {
    TLS2.get()
}

#[no_mangle]
pub extern fn set_tls2(value: i32) {
    TLS2.set(value);
}
