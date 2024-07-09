//! These functions are just here so that we can report timing for how long various things take to
//! drop. The most expensive of these in the input data, which is expensive because the kernel takes
//! time to unmap all the memory from our process. It might seem tempting to just leak these, but
//! that doesn't actually help. Benchmarks indicate that this just shifts the time to when the
//! process terminates and the total execution time remains unchanged. Probably the only way to
//! mitigate this is to hide the shutdown time in a forked subprocess. i.e. fork on startup, do the
//! work in the forked process then when we're done, signal the parent process that we're done, it
//! can then exit while the forked process cleans up.

#[tracing::instrument(skip_all, name = "Drop layout")]
pub(crate) fn free_layout(d: crate::layout::Layout) {
    drop(d);
}

#[tracing::instrument(skip_all, name = "Drop symbol DB")]
pub(crate) fn free_symbol_db(d: crate::symbol_db::SymbolDb) {
    drop(d);
}

#[tracing::instrument(skip_all, name = "Drop input data")]
pub(crate) fn free_input_data(d: crate::input_data::InputData) {
    drop(d);
}

#[tracing::instrument(skip_all, name = "Unmap output file")]
pub(crate) fn free_output(d: crate::elf_writer::SizedOutput) {
    drop(d);
}
