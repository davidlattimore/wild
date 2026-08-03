//#LinkerDriver:clang
//#ExpectDynSym:_main
//#ExpectDynSym:_exported_function
//#ExpectDynSym:_exported_data
//#ExpectDynSym:_weak_function binding=weak
//#NoDynSym:_hidden_function
//#NoDynSym:_local_function
//#DiffIgnore:section.__unwind_info

int exported_data = 20;

int exported_function(void) { return exported_data; }

__attribute__((weak)) int weak_function(void) { return 1; }

__attribute__((visibility("hidden"))) int hidden_function(void) { return 10; }

static int local_function(void) { return 12; }

int main(void) { return exported_function() + hidden_function() + local_function(); }
