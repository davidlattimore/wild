//#AbstractConfig:default
//#ExpectSection:.debug_gdb_scripts
//#DiffIgnore:section.debug_*
//#SkipArch: ppc64le
// Ignore extra .dynsym entries emitted by older GNU ld versions. See #2258
//#DiffIgnore:dynsym.*

//#Config:zlib:default
//#CompArgs:-g -Clink-arg=-Wl,--compress-debug-sections=zlib

//#Config:zstd:default
//#RequiresLinkerFlags:--compress-debug-sections=zstd
//#RequiresZstdCompression:true
//#CompArgs:-g -Clink-arg=-Wl,--compress-debug-sections=zstd

#![debugger_visualizer(gdb_script_file = "compressed-debug-gdb-scripts.gdb")]

fn main() {
    std::process::exit(42);
}
