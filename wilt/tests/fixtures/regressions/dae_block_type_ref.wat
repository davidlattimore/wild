;; Regression: DAE must scan bodies for blocktype type-index references,
;; and to scan bodies it must first call `ensure_function_bodies_parsed`
;; on the WasmModule (otherwise `function_bodies()` returns empty).
;;
;; $victim has a unique type ($vt) and one dead param — the candidate
;; pattern. But `$caller` uses $vt as a blocktype (`loop (type $vt)`).
;; If DAE shrinks $vt, the loop's expected in_arity changes and the
;; caller's stack doesn't line up. DAE must see that blocktype reference
;; and decline the candidate.

(module
  (type $vt (func (param f32) (result f32)))
  (func $victim (type $vt)
    ;; Param 0 is dead — the body just returns a constant.
    f32.const 0
  )
  (func $caller (export "caller") (param f32) (result f32)
    local.get 0
    loop (type $vt) (param f32) (result f32)
      ;; body just yields its input back
    end
  )
)
