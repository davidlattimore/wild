
# list all available just targets
default:
    @just --list


# Dump the symbol table of kernel32.lib using llvm-objdump
dump-kernel32:
    @llvm-objdump -a -t "C:/Program Files (x86)/Windows Kits/10/Lib/10.0.22621.0/um/x64/kernel32.Lib" > kernel32.dump

# Compile and link a minimal PE test using clang with wild as the linker
test-pe:
    cargo build -p wild-linker --bin wild
    mkdir -p target/testing
    clang -B./target/debug/ -fuse-ld=wild -target x86_64-pc-windows-msvc -nostdlib -e entry test_pe/test.c -o target/testing/test.exe
    ./target/testing/test.exe || echo $?