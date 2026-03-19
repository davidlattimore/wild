SECTIONS {
    mydata : {
        KEEP(*(.mydata.[0-9]))
    }
    foobar : {
        KEEP(*(foo[_-]bar))
    }
    other : {
        KEEP(*(.mydata.*))
        KEEP(*(foo*))
    }
}
