;; Inputs that never mention memory or __stack_pointer still get both.
;;#ExpectSection: Memory
;;#ExpectSection: Global
;;#ExpectSym: memory
;;#Contains: __stack_pointer

(module
  (func $start (export "_start")
    nop
  )
)
