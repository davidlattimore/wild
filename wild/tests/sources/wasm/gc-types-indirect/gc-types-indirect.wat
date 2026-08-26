;; A type used only via `R_WASM_TYPE_INDEX_LEB` (`call_indirect`) must be kept.
;; A type that nothing references must still be dropped.

;;#RunEnabled:false
;;#ExpectFuncTypeCount: 2

(module
  (type $void (func))
  (type $indirect (func (param i32) (result i32)))
  (type $unused (func (param i64) (result i64)))
  (import "env" "__indirect_function_table" (table 1 funcref))
  (func $start (export "_start") (type $void)
    i32.const 0
    i32.const 0
    call_indirect (type $indirect)
    drop
  )
)
