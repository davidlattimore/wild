;; Regression: type_gc must rewrite block/loop/if blocktype immediates
;; when types are compacted.
;;
;; Type 0 is unused. type_gc removes it, so type 1 shifts to new index 0.
;; The `block (type 1)` inside `$f` must have its immediate rewritten to
;; `(type 0)`, else the block references the wrong type and validation
;; fails.

(module
  (type $unused (func (param i32)))      ;; type 0: removed
  (type $blk    (func (result i32)))      ;; type 1 -> new 0
  (type $fn     (func))                    ;; type 2 -> new 1
  (func $f (export "f")
    (block (type $blk) (i32.const 42))
    drop
  )
)
