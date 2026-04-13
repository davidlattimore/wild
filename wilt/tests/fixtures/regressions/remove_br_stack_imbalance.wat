;; Regression: remove_unused_brs used to delete `br 0` whose immediate
;; next instruction was the block's `end`, under the reasoning that
;; "branching to the block's end is what fall-through does anyway".
;; Unsound: `br` makes the remainder of the block stack-polymorphic,
;; hiding any extra values below the br's expected stack shape. When
;; the br is removed, fall-through exposes those extras and validation
;; fails.
;;
;; Block has empty blocktype (arity 0). Before `br 0` the stack holds
;; an i32. With the br, polymorphic-after-br validates the end. Without
;; it, fall-through leaves i32 on stack at end → "values remaining on
;; stack at end of block".

(module
  (func (export "f")
    (block
      i32.const 1
      br 0
    )
  )
)
