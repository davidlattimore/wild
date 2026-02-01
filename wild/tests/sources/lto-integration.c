//#Config:clang
//#RequiresLinkerPlugin:true
//#LinkerDriver:clang
//#SkipLinker:ld
//#EnableLinker:lld
//#Compiler:clang
//#CompArgs:-flto
//#LinkArgs:-flto -Wl,--as-needed,-znow
//#DiffIgnore:section.got.plt.entsize
//#DiffIgnore:section.gnu.version_r.alignment
//#DiffIgnore:section.rodata

int main() { return 42; }
