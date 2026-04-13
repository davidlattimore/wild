;; M2 fixture: an exported helper called once. Standalone wilt's DAE
;; conservatively refuses (function is exported → assumes external
;; callers might exist). With `LinkerHints::is_internal(0) = true`,
;; DAE knows the export is the ONLY external surface and wilt-as-link-time
;; sees it as internal — last param is dead, so DAE removes it.
;;
;; Used by tests/m2_dae_with_hints.rs which compares standalone vs
;; hint-aware optimisation byte counts.

(module
  (type $vt (func (param i32 i32)))
  (func $helper (type $vt)
    ;; Reads param 0, ignores param 1.
    local.get 0
    drop
  )
  (func $caller (export "caller")
    (call $helper (i32.const 1) (i32.const 2))
  )
)
