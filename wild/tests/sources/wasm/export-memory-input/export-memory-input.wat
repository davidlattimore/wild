;;#Config:diff-name-default
;;#Object:mem-diff-name.wat
;;#ExpectSym: memory
;;#ExpectSym: _start
;;#NoSym: from_input

;;#Config:diff-name-custom
;;#Object:mem-diff-name.wat
;;#LinkArgs: --export-memory=foo
;;#ExpectSym: foo
;;#ExpectSym: _start
;;#NoSym: from_input
;;#NoSym: memory

;;#Config:same-name-default
;;#Object:mem-same-name.wat
;;#ExpectSym: memory
;;#ExpectSym: _start

;;#Config:same-name-custom
;;#Object:mem-same-name.wat
;;#LinkArgs: --export-memory=foo
;;#ExpectSym: foo
;;#ExpectSym: _start
;;#NoSym: memory

;;#Config:same-name-explicit-flag
;;#Object:mem-same-name.wat
;;#LinkArgs: --export-memory
;;#ExpectSym: memory
;;#ExpectSym: _start

;;#Config:multi-default
;;#Object:mem-multi-name.wat
;;#ExpectSym: memory
;;#ExpectSym: _start
;;#NoSym: a
;;#NoSym: b

;;#Config:multi-custom
;;#Object:mem-multi-name.wat
;;#LinkArgs: --export-memory=foo
;;#ExpectSym: foo
;;#ExpectSym: _start
;;#NoSym: a
;;#NoSym: b
;;#NoSym: memory

(module
  (func $start (export "_start")
    nop
  )
)
