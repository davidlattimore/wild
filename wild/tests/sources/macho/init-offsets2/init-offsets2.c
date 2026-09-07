//#LinkerDriver:clang
//#Object:initializer.c
//#ExpectSection:__init_offsets
//#NoSection:__mod_init_func
//#DiffIgnore:section.__unwind_info

int state;

void externally_defined_initializer(void);

__attribute__((
    used,
    section("__DATA,__mod_init_func,mod_init_funcs"))) static void (*const initializer)(void) =
    externally_defined_initializer;

int main(void) { return state; }
