//#LinkerDriver:clang

// Regression test: `thread::spawn(|| { catch_unwind(|| panic!()) })` used
// to abort at `thread_start`'s dealloc with a `free(0x7)` malloc error
// because wild:
//  - placed `__unwind_info` in an incidental TEXT gap that could be
//    zero-sized, silently dropping the whole section (no unwind
//    coverage → "failed to initiate panic, error 5"), AND
//  - faithfully propagated libstd's `0x02000000` compact_unwind
//    encoding (FRAMELESS/stack_size=0/no-saved-regs) for functions
//    that actually push a frame — e.g. edition-2015
//    `std::panicking::begin_panic`. libunwind then mis-unwinds and
//    corrupts callee-saves, crashing `thread_start` later.
//
// The fix (see `macho_writer::collect_compact_unwind_entries` and
// `apply_late_size_adjustments_epilogue` in `macho.rs`): reserve a
// proper layout slot for `__unwind_info` as the `COMMENT` output
// section, emit DWARF entries for every FDE, rewrite bogus
// `0x02000000` encodings to `0x04000000` (FRAME, fp-chain walk) for
// functions > 8 bytes, and adjacent-coalesce duplicate entries.
//
// This fixture is the default rustc edition (2015 at the time of
// writing — picks up the `begin_panic` path) for maximum coverage;
// edition 2021 lowers `panic!` to `panic_fmt` and bypasses
// `begin_panic` entirely.

fn main() {
    let h = std::thread::spawn(|| {
        let r = std::panic::catch_unwind(|| panic!("planned"));
        r.is_err()
    });
    // If the inner catch_unwind caught and returned Err, is_err() is true,
    // and join().unwrap() returns `true`. Exit 42 to match the test
    // harness's default expected exit code; anything else (0, SIGABRT,
    // "failed to initiate panic") indicates regression.
    let caught = h.join().unwrap();
    std::process::exit(if caught { 42 } else { 1 });
}
