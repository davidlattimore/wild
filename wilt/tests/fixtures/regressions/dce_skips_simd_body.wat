;; Regression: dce::rewrite_body used to silently fall back to the
;; original body when `opcode::walk` failed on an unknown opcode
;; (e.g. SIMD `0xFD`). If DCE was renumbering function indices, that
;; left stale `call N` references in SIMD-containing bodies. The fix
;; makes the whole DCE pass bail early if any body isn't walkable.

(module
  (func $dead)                              ;; will be DCE'd — not called, not exported
  (func $live (export "live") (param i32) (result i32)
    local.get 0
  )
  (func $caller (export "caller") (result i32)
    ;; SIMD op makes InstrIter fail on this body.
    v128.const i32x4 0 0 0 0
    drop
    i32.const 7
    call $live
  )
)
