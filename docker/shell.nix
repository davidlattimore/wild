{
  pkgs ? import <nixpkgs> { },
}:
pkgs.mkShell {
  nativeBuildInputs = [
    (pkgs.writeShellApplication {
      name = "gcc";
      text = ''${pkgs.lib.getExe pkgs.gcc} "$@" -B${pkgs.binutils-unwrapped-all-targets}/bin '';
    })
    (pkgs.writeShellApplication {
      name = "g++";
      text = ''${pkgs.lib.getExe' pkgs.gcc "g++"} "$@" -B${pkgs.binutils-unwrapped-all-targets}/bin '';
    })
    pkgs.binutils-unwrapped-all-targets
    pkgs.cargo-chef
    pkgs.llvmPackages_20.clang
    pkgs.lld
    pkgs.glibc.out
    pkgs.glibc.static
    pkgs.rustup
  ];

  LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib}/lib";
}
