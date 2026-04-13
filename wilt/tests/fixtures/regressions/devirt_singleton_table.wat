;; M7 fixture: a single-entry table with one ref.func, one call_indirect.
;; With LinkerHints reporting `table_targets(0) = Some(&[1])` (function
;; index 1 = $target), wilt::optimise_with_hints rewrites the
;; call_indirect into `drop ; call $target`. Standalone wilt leaves it
;; alone — no closed-world view of the table.

(module
  (type $vt (func (result i32)))
  (table 1 1 funcref)
  (elem (i32.const 0) $target)
  (func $target (type $vt) (result i32)
    i32.const 42
  )
  (func $caller (export "caller") (result i32)
    i32.const 0
    call_indirect (type $vt)
  )
)
