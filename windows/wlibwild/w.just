link:
    cargo run -p wlibwild --bin main

build-wild:
    cargo build -p wild-linker --bin wild -r

build-objs:
    clang -c basic_objs/main.c -o basic_objs/main.o
    clang -c basic_objs/function.c -o basic_objs/function.o
    clang -c basic_objs/basic.c -o basic_objs/basic.o

link-lld:
    nu -c "lld-link basic_objs/main.o basic_objs/function.o /SUBSYSTEM:CONSOLE /entry:main /nodefaultlib kernel32.lib /OUT:myprogram.exe"

wild-link: build-wild
    nu -c "../../target/release/wild.exe basic_objs/main.o basic_objs/function.o /SUBSYSTEM:CONSOLE /entry:main /nodefaultlib kernel32.lib /OUT:myprogram.exe"


dump-exe:
    @llvm-objdump --demangle --syms -C -D     myprogram.exe

run-myprogram:
    nu -c "myprogram.exe"