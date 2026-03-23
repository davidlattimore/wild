SECTIONS {
    mydata : {
        KEEP(*(.mydata.[0-9]))
    }
    helloworld : {
        KEEP(*(hello[_-]world))
    }
    other : {
        KEEP(*(.mydata.*))
        KEEP(*(hello*))
    }
}
