//#LinkerDriver:clang
//#ExpectSection:__init_offsets
//#NoSection:__mod_init_func
//#DiffIgnore:section.__unwind_info

static int state;

__attribute__((constructor)) static void first(void) { state = 1; }
__attribute__((constructor)) static void second(void) { state = state * 40 + 2; }

int main(void) { return state; }
