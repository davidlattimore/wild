mod w "windows/wlibwild/w.just"


default:
    @just w


dump-kernel32:
    @llvm-objdump -a -t "C:/Program Files (x86)/Windows Kits/10/Lib/10.0.22621.0/um/x64/kernel32.Lib" > kernel32.dump