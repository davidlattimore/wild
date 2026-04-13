;; M6 fixture: a parameterless void helper called exactly once.
;; Standalone wilt's inline_trivial leaves it alone (the function isn't
;; one of Empty/Identity/Const). With LinkerHints reporting `is_internal`
;; true for $helper AND wilt detecting the unique call site, the body
;; gets pasted into $caller; subsequent DCE reaps the orphaned $helper.

(module
  (func $helper
    nop
    nop
    nop
  )
  (func $caller (export "caller")
    call $helper
    nop
  )
)
