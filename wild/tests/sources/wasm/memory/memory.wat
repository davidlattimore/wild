(module
  (memory (export "memory") 1)
  (func $start (export "_start")
    ;; Store 42 at address 0
    i32.const 0
    i32.const 42
    i32.store
    ;; Load back and verify
    i32.const 0
    i32.load
    i32.const 42
    i32.ne
    if unreachable end
  )
)
