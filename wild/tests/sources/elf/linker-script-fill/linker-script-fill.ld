SECTIONS {
    .fill1 : {
        *(.fill1.first)
        *(.fill1.second)
    } =144

    .fill2 : {
        *(.fill2.first)
        *(.fill2.second)
    } = 0x90

    .fill3 : {
        *(.fill3.first)
        *(.fill3.second)
    } = 0x90909090

    .fill4 : {
        *(.fill4.first)
        *(.fill4.second)
    } = 0x0090

    .fill5 : {
        *(.fill5.first)
        *(.fill5.second)
    } = 0x9

    .fill6 : {
        . = . + 0x8;
        *(.fill6.first)
        . = . + 0x8;
        *(.fill6.second)
        . = . + 0x8;
    } = 0x90909090
}
