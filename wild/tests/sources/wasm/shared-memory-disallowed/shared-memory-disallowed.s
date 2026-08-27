//#LinkArgs: --shared-memory --max-memory=131072 --no-entry
//#ExpectError: --shared-memory is disallowed

  .globl _start
_start:
  .functype _start () -> ()
  end_function

  .section .custom_section.target_features,"",@
  .int8 1 # Number of target features
  .int8 45 # '-'
  .int8 10 # Length of target features string
  .ascii "shared-mem"
