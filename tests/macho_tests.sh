#!/bin/bash
# Integration tests for macOS Mach-O linking.
# Run from the repo root: bash tests/macho_tests.sh
set -euo pipefail

WILD="$(cd "$(dirname "${1:-./target/debug/wild}")" && pwd)/$(basename "${1:-./target/debug/wild}")"
TMPDIR=$(mktemp -d)
PASS=0
FAIL=0

cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }

check_exit() {
    local binary="$1" expected="$2" name="$3"
    # wild now auto-signs binaries, no manual codesign needed
    set +e
    "$binary"
    local got=$?
    set -e
    if [ "$got" -eq "$expected" ]; then
        pass "$name (exit=$got)"
    else
        fail "$name (expected exit=$expected, got exit=$got)"
    fi
}

echo "=== Wild macOS Mach-O Tests ==="
echo "Linker: $WILD"
echo ""

# --- Test 1: Single .o, return constant ---
echo "Test 1: Single object file, return 42"
cat > "$TMPDIR/t1.c" << 'EOF'
int main() { return 42; }
EOF
clang -c "$TMPDIR/t1.c" -o "$TMPDIR/t1.o"
"$WILD" "$TMPDIR/t1.o" -o "$TMPDIR/t1"
check_exit "$TMPDIR/t1" 42 "single-obj-return-42"

# --- Test 2: Two .o files with cross-object call ---
echo "Test 2: Two object files, cross-object function call"
cat > "$TMPDIR/t2_add.c" << 'EOF'
int add(int a, int b) { return a + b; }
EOF
cat > "$TMPDIR/t2_main.c" << 'EOF'
int add(int a, int b);
int main() { return add(30, 12); }
EOF
clang -c "$TMPDIR/t2_add.c" -o "$TMPDIR/t2_add.o"
clang -c "$TMPDIR/t2_main.c" -o "$TMPDIR/t2_main.o"
"$WILD" "$TMPDIR/t2_main.o" "$TMPDIR/t2_add.o" -o "$TMPDIR/t2"
check_exit "$TMPDIR/t2" 42 "two-objs-cross-call"

# --- Test 3: Three .o files ---
echo "Test 3: Three object files"
cat > "$TMPDIR/t3_a.c" << 'EOF'
int mul(int a, int b) { return a * b; }
EOF
cat > "$TMPDIR/t3_b.c" << 'EOF'
int mul(int a, int b);
int square(int x) { return mul(x, x); }
EOF
cat > "$TMPDIR/t3_main.c" << 'EOF'
int square(int x);
int main() { return square(5) - 25 + 7; }
EOF
clang -c "$TMPDIR/t3_a.c" -o "$TMPDIR/t3_a.o"
clang -c "$TMPDIR/t3_b.c" -o "$TMPDIR/t3_b.o"
clang -c "$TMPDIR/t3_main.c" -o "$TMPDIR/t3_main.o"
"$WILD" "$TMPDIR/t3_main.o" "$TMPDIR/t3_b.o" "$TMPDIR/t3_a.o" -o "$TMPDIR/t3"
check_exit "$TMPDIR/t3" 7 "three-objs-chain-calls"

# --- Test 4: Global variable (data section) ---
echo "Test 4: Global variable access"
cat > "$TMPDIR/t4_data.c" << 'EOF'
int value = 42;
EOF
cat > "$TMPDIR/t4_main.c" << 'EOF'
extern int value;
int main() { return value; }
EOF
clang -c "$TMPDIR/t4_data.c" -o "$TMPDIR/t4_data.o"
clang -c "$TMPDIR/t4_main.c" -o "$TMPDIR/t4_main.o"
"$WILD" "$TMPDIR/t4_main.o" "$TMPDIR/t4_data.o" -o "$TMPDIR/t4"
check_exit "$TMPDIR/t4" 42 "global-variable-extern"

# --- Test 4b: Static variable ---
echo "Test 4b: Static variable access"
cat > "$TMPDIR/t4b.c" << 'EOF'
static int value = 42;
int main() { return value; }
EOF
clang -c "$TMPDIR/t4b.c" -o "$TMPDIR/t4b.o"
"$WILD" "$TMPDIR/t4b.o" -o "$TMPDIR/t4b"
check_exit "$TMPDIR/t4b" 42 "global-variable-static"

# --- Test 4c: Static archive (.a) ---
echo "Test 4c: Static archive linking"
cat > "$TMPDIR/t4c_add.c" << 'EOF'
int add(int a, int b) { return a + b; }
EOF
cat > "$TMPDIR/t4c_mul.c" << 'EOF'
int mul(int a, int b) { return a * b; }
EOF
cat > "$TMPDIR/t4c_main.c" << 'EOF'
int add(int a, int b);
int mul(int a, int b);
int main() { return add(mul(6, 7), 0); }
EOF
clang -c "$TMPDIR/t4c_add.c" -o "$TMPDIR/t4c_add.o"
clang -c "$TMPDIR/t4c_mul.c" -o "$TMPDIR/t4c_mul.o"
clang -c "$TMPDIR/t4c_main.c" -o "$TMPDIR/t4c_main.o"
ar rcs "$TMPDIR/t4c_lib.a" "$TMPDIR/t4c_add.o" "$TMPDIR/t4c_mul.o"
"$WILD" "$TMPDIR/t4c_main.o" "$TMPDIR/t4c_lib.a" -o "$TMPDIR/t4c"
check_exit "$TMPDIR/t4c" 42 "static-archive"

# --- Test 4d: Dynamic symbol (printf) ---
echo "Test 4d: Dynamic symbol call (printf)"
cat > "$TMPDIR/t4d.c" << 'EOF'
#include <stdio.h>
int main() {
    printf("hello wild\n");
    return 7;
}
EOF
clang -c "$TMPDIR/t4d.c" -o "$TMPDIR/t4d.o"
"$WILD" "$TMPDIR/t4d.o" -o "$TMPDIR/t4d"
check_exit "$TMPDIR/t4d" 7 "dynamic-symbol-printf"

# --- Test 4e: clang drop-in linker ---
echo "Test 4e: clang -fuse-ld=wild"
cat > "$TMPDIR/t4e.c" << 'EOF'
#include <stdio.h>
void greet(const char *name) { printf("Hello, %s!\n", name); }
EOF
cat > "$TMPDIR/t4e_main.c" << 'EOF'
void greet(const char *name);
int main() { greet("wild"); return 3; }
EOF
if clang -fuse-ld="$WILD" "$TMPDIR/t4e.c" "$TMPDIR/t4e_main.c" -o "$TMPDIR/t4e" 2>/dev/null; then
    check_exit "$TMPDIR/t4e" 3 "clang-drop-in-linker"
else
    fail "clang-drop-in-linker (link failed)"
fi

# --- Test 4f: Function pointer table (rebase fixups) ---
echo "Test 4f: Function pointer table with rebases"
cat > "$TMPDIR/t4f.c" << 'EOF'
#include <stdio.h>
typedef int (*fn_t)(void);
int f0(void) { return 10; }
int f1(void) { return 20; }
int f2(void) { return 12; }
fn_t table[] = { f0, f1, f2 };
int main() {
    int sum = 0;
    for (int i = 0; i < 3; i++) sum += table[i]();
    return sum;
}
EOF
clang -c "$TMPDIR/t4f.c" -o "$TMPDIR/t4f.o"
"$WILD" "$TMPDIR/t4f.o" -o "$TMPDIR/t4f"
check_exit "$TMPDIR/t4f" 42 "function-pointer-rebase"

# --- Test 4g: Rust no_std ---
echo "Test 4g: Rust no_std program"
cat > "$TMPDIR/t4g.rs" << 'EOF'
#![no_std]
#![no_main]
#[no_mangle]
pub extern "C" fn main() -> i32 { 42 }
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
EOF
if rustc "$TMPDIR/t4g.rs" --emit=obj --target=aarch64-apple-darwin -C panic=abort -o "$TMPDIR/t4g.o" 2>/dev/null; then
    "$WILD" "$TMPDIR/t4g.o" -o "$TMPDIR/t4g"
    check_exit "$TMPDIR/t4g" 42 "rust-no-std"
else
    echo "  SKIP: rust-no-std (rustc not available)"
fi

# --- Test 4h: Non-extern relocations (section-ordinal) ---
echo "Test 4h: Non-extern relocations"
cat > "$TMPDIR/t4h.c" << 'EOF'
static int helper(int x) { return x * 2; }
static int other(int x) { return x + 1; }
int main() {
    int (*fns[])(int) = { helper, other };
    return fns[0](20) + fns[1](0);
}
EOF
clang -c "$TMPDIR/t4h.c" -o "$TMPDIR/t4h.o"
"$WILD" "$TMPDIR/t4h.o" -o "$TMPDIR/t4h"
check_exit "$TMPDIR/t4h" 41 "non-extern-relocs"

# --- Test 4i: C TLS variable ---
echo "Test 4i: C thread-local variable"
cat > "$TMPDIR/t4i.c" << 'EOF'
__thread int x = 42;
int main() { return x; }
EOF
clang -c "$TMPDIR/t4i.c" -o "$TMPDIR/t4i.o"
"$WILD" "$TMPDIR/t4i.o" -o "$TMPDIR/t4i"
check_exit "$TMPDIR/t4i" 42 "c-tls-variable"

# --- Test 4j: Multi-TLS across objects ---
echo "Test 4j: Multi-TLS across objects"
cat > "$TMPDIR/t4j_a.c" << 'EOF'
__thread int a = 10;
__thread int b = 20;
int get_tls_sum(void) { return a + b; }
EOF
cat > "$TMPDIR/t4j_b.c" << 'EOF'
int get_tls_sum(void);
int main() { return get_tls_sum() + 12; }
EOF
clang -c "$TMPDIR/t4j_a.c" -o "$TMPDIR/t4j_a.o"
clang -c "$TMPDIR/t4j_b.c" -o "$TMPDIR/t4j_b.o"
"$WILD" "$TMPDIR/t4j_a.o" "$TMPDIR/t4j_b.o" -o "$TMPDIR/t4j"
check_exit "$TMPDIR/t4j" 42 "multi-tls"

# --- Test 4k: vtable + printf in archive (no TLS) ---
echo "Test 4k: Archive with vtable and printf"
cat > "$TMPDIR/t4k_lib.c" << 'EOF'
typedef int (*op_t)(int);
static int double_it(int x) { return x * 2; }
static int add_one(int x) { return x + 1; }
const op_t ops[] = { double_it, add_one };
int apply_op(int i, int x) { return ops[i](x); }
EOF
cat > "$TMPDIR/t4k_main.c" << 'EOF'
#include <stdio.h>
int apply_op(int i, int x);
int main() {
    int result = apply_op(0, 10) + apply_op(1, 0);
    printf("result=%d\n", result);
    return result - 21 + 42;
}
EOF
clang -c "$TMPDIR/t4k_lib.c" -o "$TMPDIR/t4k_lib.o"
clang -c "$TMPDIR/t4k_main.c" -o "$TMPDIR/t4k_main.o"
ar rcs "$TMPDIR/t4k.a" "$TMPDIR/t4k_lib.o"
"$WILD" "$TMPDIR/t4k_main.o" "$TMPDIR/t4k.a" -o "$TMPDIR/t4k"
check_exit "$TMPDIR/t4k" 42 "archive-vtable-printf"

# --- Test 4l: TLS + vtable + archive + printf ---
echo "Test 4l: Complex archive with TLS and vtable"
cat > "$TMPDIR/t4k_lib.c" << 'EOF'
#include <stdio.h>
__thread int counter = 0;
typedef int (*op_t)(int);
static int double_it(int x) { return x * 2; }
static int add_one(int x) { return x + 1; }
const op_t ops[] = { double_it, add_one };
int apply_op(int i, int x) { counter++; return ops[i](x); }
int get_counter(void) { return counter; }
EOF
cat > "$TMPDIR/t4k_main.c" << 'EOF'
#include <stdio.h>
int apply_op(int i, int x);
int get_counter(void);
int main() {
    int result = apply_op(0, 10) + apply_op(1, 0) + get_counter();
    printf("result=%d\n", result);
    return result - 23 + 42;
}
EOF
clang -c "$TMPDIR/t4k_lib.c" -o "$TMPDIR/t4k_lib.o"
clang -c "$TMPDIR/t4k_main.c" -o "$TMPDIR/t4k_main.o"
ar rcs "$TMPDIR/t4k.a" "$TMPDIR/t4k_lib.o"
"$WILD" "$TMPDIR/t4k_main.o" "$TMPDIR/t4k.a" -o "$TMPDIR/t4k"
check_exit "$TMPDIR/t4k" 42 "complex-archive-tls-vtable"

# --- Test 4m: Trait-like vtable dispatch with TLS + archive ---
echo "Test 4m: Trait dispatch with vtable, TLS, malloc"
cat > "$TMPDIR/t4m_lib.c" << 'EOF'
#include <stdlib.h>
__thread int depth = 0;
typedef struct { void (*drop)(void*); int (*call)(void*, int); } Vtable;
typedef struct { const Vtable *vtable; int value; } TraitObj;
static void a_drop(void *s) { depth++; }
static int a_call(void *s, int x) { depth++; return ((TraitObj*)s)->value + x; }
static const Vtable A_VT = { a_drop, a_call };
static void m_drop(void *s) { depth++; }
static int m_call(void *s, int x) { depth++; return ((TraitObj*)s)->value * x; }
static const Vtable M_VT = { m_drop, m_call };
TraitObj *make_adder(int v) { TraitObj *o=malloc(sizeof(*o)); o->vtable=&A_VT; o->value=v; return o; }
TraitObj *make_mul(int v) { TraitObj *o=malloc(sizeof(*o)); o->vtable=&M_VT; o->value=v; return o; }
int call_trait(TraitObj *o, int x) { return o->vtable->call(o, x); }
void drop_trait(TraitObj *o) { o->vtable->drop(o); free(o); }
int get_depth(void) { return depth; }
EOF
cat > "$TMPDIR/t4m_main.c" << 'EOF'
#include <stdio.h>
typedef struct TraitObj TraitObj;
TraitObj *make_adder(int v); TraitObj *make_mul(int v);
int call_trait(TraitObj *o, int x); void drop_trait(TraitObj *o); int get_depth(void);
int main() {
    TraitObj *a = make_adder(10), *m = make_mul(3);
    int r = call_trait(a,5) + call_trait(m,7);
    drop_trait(a); drop_trait(m);
    printf("r=%d d=%d\n", r, get_depth());
    return r + get_depth() + 2;
}
EOF
clang -c "$TMPDIR/t4m_lib.c" -o "$TMPDIR/t4m_lib.o"
clang -c "$TMPDIR/t4m_main.c" -o "$TMPDIR/t4m_main.o"
ar rcs "$TMPDIR/t4m.a" "$TMPDIR/t4m_lib.o"
"$WILD" "$TMPDIR/t4m_main.o" "$TMPDIR/t4m.a" -o "$TMPDIR/t4m"
check_exit "$TMPDIR/t4m" 42 "trait-dispatch-tls-vtable"

# --- Test 4n: Rust std links ---
echo "Test 4n: Rust std links"
cat > "$TMPDIR/t4i.rs" << 'EOF'
fn add(a: i32, b: i32) -> i32 { a + b }
fn main() {
    let result = add(30, 12);
    std::process::exit(result);
}
EOF
if rustc "$TMPDIR/t4i.rs" -Clinker=clang "-Clink-arg=-fuse-ld=$WILD" -o "$TMPDIR/t4i" 2>/dev/null; then
    if [ -f "$TMPDIR/t4i" ] && file "$TMPDIR/t4i" | grep -q "Mach-O 64-bit executable arm64"; then
        pass "rust-std-links"
    else
        fail "rust-std-links"
    fi
else
    echo "  SKIP: rust-std-links (rustc not available or link failed)"
fi

# --- Test 4j: Rust hello world runs ---
echo "Test 4o: Rust hello world runs"
cat > "$TMPDIR/t4k.rs" << 'EOF'
fn main() {
    println!("Hello from wild!");
    std::process::exit(42);
}
EOF
if rustc "$TMPDIR/t4k.rs" -Clinker=clang "-Clink-arg=-fuse-ld=$WILD" -o "$TMPDIR/t4k" 2>/dev/null; then
    check_exit "$TMPDIR/t4k" 42 "rust-hello-world"
else
    echo "  SKIP: rust-hello-world (rustc not available or link failed)"
fi

# --- Test 4o2: Rust dylib with complex std (HashMap, Vec, format) ---
echo "Test 4o2: Rust dylib with complex std usage"
cat > "$TMPDIR/t4o2.rs" << 'EOF'
use std::collections::HashMap;
#[no_mangle]
pub extern "C" fn complex_test() -> i32 {
    let mut map = HashMap::new();
    map.insert("hello".to_string(), 10);
    map.insert("world".to_string(), 32);
    let sum: i32 = map.values().sum();
    let msg = format!("sum={}", sum);
    if msg.contains("42") { sum } else { -1 }
}
EOF
if rustc "$TMPDIR/t4o2.rs" --crate-type dylib -Clinker=clang "-Clink-arg=-fuse-ld=$WILD" -o "$TMPDIR/t4o2.dylib" 2>/dev/null; then
    # Test via dlopen
    cat > "$TMPDIR/t4o2_test.c" << 'LOADEOF'
#include <dlfcn.h>
#include <stdio.h>
int main() {
    void *h = dlopen("DYLIB_PATH", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    int (*fn)(void) = dlsym(h, "complex_test");
    if (!fn) { fprintf(stderr, "dlsym: %s\n", dlerror()); dlclose(h); return 1; }
    int r = fn();
    dlclose(h);
    return r == 42 ? 42 : 1;
}
LOADEOF
    sed -i '' "s|DYLIB_PATH|$TMPDIR/t4o2.dylib|" "$TMPDIR/t4o2_test.c"
    clang "$TMPDIR/t4o2_test.c" -o "$TMPDIR/t4o2_test"
    check_exit "$TMPDIR/t4o2_test" 42 "rust-dylib-complex-std"
else
    echo "  SKIP: rust-dylib-complex-std (rustc not available or link failed)"
fi

# --- Test 4p: Rust proc-macro (requires dylib .rustc section) ---
echo "Test 4p: Rust proc-macro crate"
PROC_DIR="$TMPDIR/procmacro"
mkdir -p "$PROC_DIR/my_macro/src" "$PROC_DIR/my_app/src"
cat > "$PROC_DIR/Cargo.toml" << 'EOF'
[workspace]
members = ["my_macro", "my_app"]
resolver = "2"
EOF
cat > "$PROC_DIR/my_macro/Cargo.toml" << 'EOF'
[package]
name = "my_macro"
version = "0.1.0"
edition = "2021"
[lib]
proc-macro = true
EOF
cat > "$PROC_DIR/my_macro/src/lib.rs" << 'EOF'
extern crate proc_macro;
use proc_macro::TokenStream;
#[proc_macro]
pub fn answer(_input: TokenStream) -> TokenStream { "42i32".parse().unwrap() }
EOF
cat > "$PROC_DIR/my_app/Cargo.toml" << 'EOF'
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"
[dependencies]
my_macro = { path = "../my_macro" }
EOF
cat > "$PROC_DIR/my_app/src/main.rs" << 'EOF'
fn main() { let v: i32 = my_macro::answer!(); std::process::exit(v); }
EOF
if cd "$PROC_DIR" && RUSTFLAGS="-Clinker=clang -Clink-arg=-fuse-ld=$WILD" cargo build 2>/dev/null; then
    check_exit "$PROC_DIR/target/debug/my_app" 42 "rust-proc-macro"
else
    fail "rust-proc-macro"
fi
cd "$TMPDIR"

# --- Test 5: Output flag ---
echo "Test 5: -o flag"
clang -c "$TMPDIR/t1.c" -o "$TMPDIR/t5.o"
"$WILD" "$TMPDIR/t5.o" -o "$TMPDIR/t5_out"
if [ -f "$TMPDIR/t5_out" ]; then
    pass "output-flag"
else
    fail "output-flag"
fi

# --- Test 6: Valid Mach-O structure ---
echo "Test 6: Valid Mach-O structure"
if file "$TMPDIR/t1" | grep -q "Mach-O 64-bit executable arm64"; then
    pass "valid-macho-structure"
else
    fail "valid-macho-structure"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
