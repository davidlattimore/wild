(module
  (global $counter (mut i32) (i32.const 0))
  (func $start (export "_start")
    ;; Increment counter: 0 -> 1
    global.get $counter
    i32.const 1
    i32.add
    global.set $counter
    ;; Verify counter == 1
    global.get $counter
    i32.const 1
    i32.ne
    if unreachable end
  )
)
