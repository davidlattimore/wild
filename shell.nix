{
  pkgs ? import <nixpkgs> { },
}:
pkgs.mkShell {
  nativeBuildInputs = [
    # Write a wrapper for GCC that passes -B to *unwrapped* binutils.
    # This ensures that if -fuse-ld=bfd is used, gcc picks up unwrapped ld.bfd
    # instead of the hardcoded wrapper search directory.
    # We pass it last because apparently gcc likes picking ld from the *first* -B,
    # which we want our wild target directory to be if passed.
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
