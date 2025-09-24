__thread int tvar3 = 80;

// These get overridden in the main file.
__attribute__((weak)) int weak_var = 20;
__attribute__((weak)) __thread int weak_tvar = 21;

// These don't get overridden.
__attribute__((weak)) int weak_var2 = 80;
__attribute__((weak)) __thread int weak_tvar2 = 81;

extern __thread int tvar2;

static __thread int tvar_local = 8;
static __thread int tvar_local2 = 70;

int value42 = 42;

void set_tvar2(int v) { tvar2 = v; }

void set_tvar3(int v) { tvar3 = v; }

void set_tvar_local(int v) { tvar_local = v; }

int get_tvar_local(void) { return tvar_local; }

void set_tvar_local2(int v) { tvar_local2 = v; }

int get_tvar_local2(void) { return tvar_local2; }

int get_weak_var(void) { return weak_var; }

int get_weak_tvar(void) { return weak_tvar; }

int get_weak_var2(void) { return weak_var2; }

int get_weak_tvar2(void) { return weak_tvar2; }

static int return10() { return 10; }

int compute_value10(void) __attribute__((ifunc("resolve_compute_value10")));

static void* resolve_compute_value10(void) { return return10; }

int sometimes_weak_fn(void) { return 42; }

typedef int (*get_int_fn_t)(void);

get_int_fn_t sometimes_weak_fn_ptr = sometimes_weak_fn;

get_int_fn_t get_sometimes_weak_fn_ptr(void) { return sometimes_weak_fn_ptr; }

int black_box(int v) { return v; }

// This function is also defined in libc-integration-0b.c. The definition here
// should be used.
int __attribute__((weak)) weak_fn3(void) { return 15; }

__attribute__((weak, visibility(("hidden")))) int atoi(const char* bytes) {
  return 77;
}
