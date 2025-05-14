//#Object:preinit-array.s
//#LinkerDriver:gcc
//#DiffIgnore:segment.LOAD.RW.alignment
//#DiffIgnore:section.data
//#DiffIgnore:section.rodata
//#DiffIgnore:.dynamic.DT_PREINIT_ARRAY
//#Arch: x86_64
//#RequiresGlibc:true

int exit_code;

void preinit() {
    exit_code = 42;
}

int main() {
    return exit_code;
}
