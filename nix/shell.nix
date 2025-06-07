{
  pkgs ? import <nixpkgs> { },
}:
pkgs.mkShell {
  packages = [
    pkgs.binutils-unwrapped-all-targets
    pkgs.cargo-chef
    pkgs.llvmPackages_20.clang
    pkgs.lld
    pkgs.glibc.out
    pkgs.glibc.static
    pkgs.rustup
  ] ++ (pkgs.callPackage ./. { }).gccWrappers;

  env.LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.stdenv.cc.cc.lib ];
}
