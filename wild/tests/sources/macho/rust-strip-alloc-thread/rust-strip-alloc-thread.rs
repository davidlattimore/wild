//#LinkerDriver:clang
//#RustFlags:-Cstrip=debuginfo

// Broader strip=debuginfo regression: exercises alloc, threading,
// TLS and a caught panic together. These are the paths historically
// broken by wild's indirect-symbol-table mis-emission (see
// `rust-strip-debuginfo.rs` for the two fix stages). If any of the
// __nl_symbol_ptrs that `strip` rewrites becomes mis-indexed, one
// of the four checks below SIGSEGVs instead of returning 42.

use std::cell::Cell;
use std::panic;
use std::thread;

thread_local!(static COUNTER: Cell<u32> = const { Cell::new(0) });

fn main() {
    // alloc + Vec — exercises malloc chain through __got binds.
    let v: Vec<u32> = (0..1000).collect();
    assert_eq!(v.iter().sum::<u32>(), 499_500);

    // caught panic — exercises __unwind_info / personality route.
    let caught = panic::catch_unwind(|| {
        if v.len() != 1000 {
            panic!("should not happen");
        }
        42u32
    })
    .unwrap();
    assert_eq!(caught, 42);

    // threading + TLS — exercises pthread_* binds and TLV thunks.
    COUNTER.with(|c| c.set(1));
    let handle = thread::spawn(|| {
        COUNTER.with(|c| {
            assert_eq!(c.get(), 0);
            c.set(99);
            c.get()
        })
    });
    let child_val = handle.join().unwrap();
    assert_eq!(child_val, 99);
    assert_eq!(COUNTER.with(Cell::get), 1);

    std::process::exit(42);
}
