//#AbstractConfig:default
//#DiffIgnore:section.data
//#DiffIgnore:section.data.alignment
//#DiffIgnore:section.rodata
//#DiffIgnore:section.rodata.alignment
//#RequiresGlibc:true

//#Config:pie:default
//#CompArgs:-fpie
//#LinkArgs:--cc=gcc -Wl,-z,now

int exit_code = 2;

static void impl(void) {
    exit_code += 40;
}
static void *resolver(void) {
    return impl;
}
void *ifunc(void) __attribute__((ifunc("resolver")));

int main() {
    ifunc();
    return exit_code;
}
