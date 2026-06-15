(module
  (func $callee (result i32)
    i32.const 42
  )
  (func $start (export "_start")
    call $callee
    i32.const 42
    i32.ne
    if unreachable end
  )
)
