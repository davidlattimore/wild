//#DoesNotContain: env

    .functype    optional () -> ()
    .weak    optional

    .globl    _start
_start:
    .functype    _start () -> ()
    i32.const    optional@TBREL
    i32.const    0
    i32.ne
    if
      unreachable
    end_if
    end_function
