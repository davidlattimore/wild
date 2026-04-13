;; Regression: simplify_locals spun forever when a `local.set X` was
;; followed by `local.get/set/tee Y` for a DIFFERENT local — the match
;; arm neither broke out of the loop nor advanced the scan cursor when
;; the index didn't match X.
;;
;; A 1-second test timeout isn't really a proof; the better assertion
;; is simply "wilt::optimise returns" within a reasonable wall budget.

(module
  (func (export "f") (local i32 i32)
    i32.const 1
    local.set 0    ;; dead: local 0 never read. old pass spun scanning forward.
    local.get 1    ;; different local — the guarded match arm fell through.
    drop
  )
)
