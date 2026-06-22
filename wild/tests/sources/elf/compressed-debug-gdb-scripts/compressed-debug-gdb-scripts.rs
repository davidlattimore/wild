//#AbstractConfig:default
//#ExpectSection:.debug_gdb_scripts
//#DiffIgnore:section.debug_*
//#SkipArch: ppc64le

//#Config:zlib:default
//#CompArgs:-g -Clink-arg=-Wl,--compress-debug-sections=zlib

//#Config:zstd:default
//#RequiresLinkerFlags:--compress-debug-sections=zstd
//#CompArgs:-g -Clink-arg=-Wl,--compress-debug-sections=zstd

#![debugger_visualizer(gdb_script_file = "compressed-debug-gdb-scripts.gdb")]

fn main() {
    std::process::exit(42);
}
