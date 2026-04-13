;; Regression: type_gc must remap the type index carried by function
;; imports. Before the fix, after type compaction the import still
;; pointed at the old index → either out of bounds or wrong arity.
;;
;; Padded with `nop`s so the code section's body-size LEB isn't a byte
;; value that type_gc's conservative byte-scanner would mistake for a
;; block/call_indirect opcode. That scanner is an intentional
;; over-approximation — it's fine for correctness but would otherwise
;; cause this fixture to fail to actually exercise type removal.

(module
  (type $unused (func (param i32)))      ;; type 0: removed
  (type $imp_ty (func (param i64)))       ;; type 1 -> new 0 (used by import)
  (type $fn     (func))                    ;; type 2 -> new 1 (used by $f)
  (import "env" "ext" (func (type $imp_ty)))
  (func $f (export "f")
    nop nop nop nop nop nop nop nop
  )
)
