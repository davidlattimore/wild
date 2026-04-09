//#LinkerDriver:clang

use std::cell::Cell;
use std::thread;

thread_local!(static FOO: Cell<u32> = Cell::new(1));

fn main() {
    assert_eq!(FOO.get(), 1);
    FOO.set(2);
    let t = thread::spawn(move || {
        assert_eq!(FOO.get(), 1);
        FOO.set(3);
    });
    t.join().unwrap();
    assert_eq!(FOO.get(), 2);
    std::process::exit(42);
}
