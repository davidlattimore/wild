// This file is used to verify that rust is able to use linker-plugin LTO.

fn main() {
    // The catch_unwind is needed since otherwise output from rustc with LLVM 22 is accepted by the
    // LLVM 20 linker plugin.
    let _ = std::panic::catch_unwind(|| {});
}
