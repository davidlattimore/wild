//#AbstractConfig:default
//#ExpectSection:.debug_gdb_scripts
//#DiffIgnore:section.debug_*
//#SkipArch: ppc64le

//#Config:zlib:default
//#CompArgs:-g -Clink-arg=-Wl,--compress-debug-sections=zlib
// TODO: wild should emit one zlib stream per compressed section
//#DiffIgnore:debug_info

//#Config:zstd:default
//#RequiresLinkerFlags:--compress-debug-sections=zstd
//#CompArgs:-g -Clink-arg=-Wl,--compress-debug-sections=zstd

#![debugger_visualizer(gdb_script_file = "compressed-debug-gdb-scripts.gdb")]

fn main() {
    std::process::exit(42);
}
