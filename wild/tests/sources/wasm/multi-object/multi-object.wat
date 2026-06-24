;;#Object:multi-object2.wat

(module
  (type $i32_ret (func (result i32)))
  (import "env" "helper" (func $helper (type $i32_ret)))
  (func $start (export "_start")
    call $helper
    i32.const 42
    i32.ne
    if unreachable end
  )
)
