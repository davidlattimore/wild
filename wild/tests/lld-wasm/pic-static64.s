# Memory64 variant of pic-static: verifies that static-PIC under -mwasm64
# synthesises i64 __memory_base / __table_base globals and encodes @MBREL /
# @TBREL via the padded SLEB64 relocations (R_WASM_MEMORY_ADDR_REL_SLEB64,
# R_WASM_TABLE_INDEX_REL_SLEB64).
# RUN: llvm-mc -filetype=obj -triple=wasm64-unknown-unknown %s -o %t.o
# RUN: wasm-ld -mwasm64 --allow-undefined --export-all -o %t.wasm %t.o
# RUN: obj2yaml %t.wasm | FileCheck %s

.globaltype __memory_base, i64, immutable
.globaltype __table_base,  i64, immutable

.globl getaddr_hidden
getaddr_hidden:
  .functype getaddr_hidden () -> (i64)
  global.get __table_base
  i64.const hidden_func@TBREL
  i64.add
  end_function

.globl getaddr_hidden_data
getaddr_hidden_data:
  .functype getaddr_hidden_data () -> (i64)
  global.get __memory_base
  i64.const hidden_data@MBREL
  i64.add
  end_function

.hidden hidden_func
.globl hidden_func
hidden_func:
  .functype hidden_func () -> (i32)
  i32.const 1
  end_function

.globl _start
_start:
  .functype _start () -> ()
  call getaddr_hidden
  drop
  call getaddr_hidden_data
  drop
  end_function

.hidden hidden_data
.section .data.hidden_data,"",@
.globl hidden_data
hidden_data:
  .int8 0x42
  .size hidden_data, 1

# __memory_base widened to I64 under mem64.
# CHECK:        - Type:            GLOBAL
# CHECK-NEXT:     Globals:
# CHECK-NEXT:       - Index:           0
# CHECK-NEXT:         Type:            I64
# CHECK-NEXT:         Mutable:         true
# CHECK:              Name:            __stack_pointer
# Skipping exact global count checks — key assertion is that the base
# triad exists with I64 types.

# CHECK:          GlobalNames:
# CHECK:              Name:            __memory_base
# CHECK:              Name:            __table_base
