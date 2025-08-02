{
  pkgs ? import <nixpkgs> { },
  craneLib,
}:
pkgs.mkShell {
  packages = [
    pkgs.binutils-unwrapped-all-targets
    pkgs.cargo-chef
    pkgs.llvmPackages_20.clang
    pkgs.clang-tools
    pkgs.lld
    pkgs.glibc.out
    pkgs.glibc.static
    pkgs.rustup
  ] ++ (pkgs.callPackage ./. { inherit craneLib; }).gccWrappers;

  env.LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.stdenv.cc.cc.lib ];
}
