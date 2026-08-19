;;#AbstractConfig:base
;;#RunEnabled:false

;;#Config:default-gc:base
;;#ExpectFuncTypeCount: 1

;;#Config:no-gc-sections:base
;;#LinkArgs: --no-gc-sections
;;#ExpectFuncTypeCount: 2

(module
  (type $void (func))
  (type $dead (func (param i32 i32 i32) (result i32)))
  (type $unused (func (param i64) (result i64)))
  (func (type $dead)
    local.get 0
    local.get 1
    i32.add
    local.get 2
    i32.add
  )
  (func $start (export "_start") (type $void)
    nop
  )
)
