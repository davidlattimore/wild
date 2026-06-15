;;#Object:multi-object2.wat
;;#SkipRun
(module
  (type $void_to_void (func))
  (import "env" "helper" (func $helper (type $void_to_void)))
  (func $start (export "_start")
    call $helper
  )
)
