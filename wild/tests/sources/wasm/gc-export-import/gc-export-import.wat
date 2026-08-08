;; Exporting an import is a GC root of the binding. If another object defines the
;; symbol, the definition must stay live and the host import must disappear.
;;#Object:gc-export-import-def.c
;;#ExpectSym: gc_exported_import
;;#ExpectFuncImportCount: 0

(module
  (type $void (func))
  (import "env" "gc_exported_import" (func $gc_exported_import (type $void)))
  (export "gc_exported_import" (func $gc_exported_import))
  (func $start (export "_start"))
)
