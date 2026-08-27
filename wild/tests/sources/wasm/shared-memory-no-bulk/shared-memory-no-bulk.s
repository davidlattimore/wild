//#LinkArgs: --shared-memory --max-memory=131072 --no-entry
//#ExpectError: 'bulk-memory' feature must be used in order to use shared memory

  .globl _start
_start:
  .functype _start () -> ()
  end_function

  .section .custom_section.target_features,"",@
  .int8 1 # Number of target features
  .int8 43 # '+'
  .int8 7 # Length of target features string
  .ascii "atomics"
