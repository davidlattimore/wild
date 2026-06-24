;;#RunEnabled:false
;;#LinkArgs:--no-gc-sections
;;#ExpectSection:Data

(module
  (memory (export "memory") 1)
  (data (i32.const 0) "\2A\00\00\00")
  (func $start (export "_start")
    nop
  )
)
