(module
  (func $add (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add
  )
  (func $start (export "_start")
    i32.const 40
    i32.const 2
    call $add
    i32.const 42
    i32.ne
    if unreachable end
  )
)
