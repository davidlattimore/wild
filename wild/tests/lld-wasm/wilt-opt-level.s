# Verify wilt fires under `-O1` and not under `-O0`.
#
# `fold_me` contains `i32.const 1 + i32.const 2 + i32.add`, which wilt's
# const-fold pass collapses to `i32.const 3`. Both symbols are force-
# exported so wild's own GC doesn't touch them — the only way the body
# shrinks is through wilt.

# RUN: llvm-mc -filetype=obj -triple=wasm32-unknown-unknown %s -o %t.o

# RUN: wasm-ld --export=fold_me --export=_start -o %t.O0.wasm %t.o
# RUN: obj2yaml %t.O0.wasm | FileCheck %s --check-prefix=O0

# RUN: wasm-ld -O1 --export=fold_me --export=_start -o %t.O1.wasm %t.o
# RUN: obj2yaml %t.O1.wasm | FileCheck %s --check-prefix=O1

# O0: Body: 410141026A0B
# O1: Body: 41030B

.globl fold_me
fold_me:
  .functype fold_me () -> (i32)
  i32.const 1
  i32.const 2
  i32.add
  end_function

.globl _start
_start:
  .functype _start () -> ()
  end_function
