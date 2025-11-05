{
  lib,
  pkgs,
  stdenv,
  gccStdenv,
  clangStdenv,
  fetchpatch,
  makeBinaryWrapper,
  craneLib,
  versionCheckHook,
  buildPackages,
  runCommandCC,
  hello,
  clang,
  clang-tools,
  binutils-unwrapped-all-targets,
  gcc,
  glibc,
  lld,
}:
assert lib.assertMsg (lib.versionAtLeast pkgs.rustc.version "1.89.0")
  "Wild requires at least Rust 1.89.0, this instance of nixpkgs has Rust ${pkgs.rustc.version}";

let
  # Write a wrapper for GCC that passes -B to *unwrapped* binutils.
  # This ensures that if -fuse-ld=bfd is used, gcc picks up unwrapped ld.bfd
  # instead of the hardcoded wrapper search directory.
  # We pass it last because apparently gcc likes picking ld from the *first* -B,
  # which we want our wild target directory to be if passed.
  gccWrapper = stdenv.mkDerivation {
    inherit (gcc) meta name;
    dontUnpack = true;
    dontConfigure = true;
    dontInstall = true;

    buildInputs = [ makeBinaryWrapper ];
    buildPhase = ''
      runHook preBuild

      makeWrapper ${lib.getExe gcc} $out/bin/gcc \
        --append-flag -B${binutils-unwrapped-all-targets}/bin

      runHook postBuild
    '';

  };

  gppWrapper = stdenv.mkDerivation {
    dontUnpack = true;
    dontConfigure = true;
    dontInstall = true;

    name = "g++-wrapped";
    buildInputs = [ makeBinaryWrapper ];
    buildPhase = ''
      runHook preBuild

      makeWrapper ${lib.getExe' gcc "g++"} $out/bin/g++ \
        --append-flag -B${binutils-unwrapped-all-targets}/bin

      runHook postBuild
    '';
    meta = gcc.meta // {
      mainProgram = "g++";
    };
  };

  cargoToml = builtins.fromTOML (builtins.readFile ../Cargo.toml);

  fs = lib.fileset;

  # Only track files checked into git, and then specify files to ignore that
  # are tracked in git too.
  # This can reduce rebuilds with Nix.
  files = fs.difference (fs.gitTracked ../.) (
    fs.unions [
      ../.gitignore
      ../flake.lock
      ../docker
      ../test-config.toml.sample
      ../test-config-ci.toml
      ../.dockerignore
      ../cackle.toml
      ../rustfmt.toml
      ../LICENSE-MIT
      ../LICENSE-APACHE
      (fs.fileFilter (file: file.hasExt "md") ../.)
      (fs.fileFilter (file: file.hasExt "nix") ../.)
    ]
  );

  commonArgs = {
    pname = "wild";
    inherit (cargoToml.workspace.package) version;

    strictDeps = true;
    src = fs.toSource {
      root = ../.;
      fileset = files;
    };

    # wild's tests compare the outputs of several different linkers. nixpkgs's
    # patching and wrappers change the output behavior, so we must make sure
    # that their behavior is compatible.
    checkInputs = [
      glibc.out
      glibc.static
    ];
    preCheck = ''
      export LD_LIBRARY_PATH=${
        lib.makeLibraryPath [
          stdenv.cc.cc.lib
        ]
      }:$LD_LIBRARY_PATH

      export PATH=${
        lib.makeBinPath [
          binutils-unwrapped-all-targets
          clang
          clang-tools
          gccWrapper
          gppWrapper
          lld
        ]
      }:$PATH
    '';
  };
in
craneLib.buildPackage (
  commonArgs
  // rec {
    cargoArtifacts = craneLib.buildDepsOnly commonArgs;

    cargoBuildCommand = "cargo build --profile release -p wild-linker";

    doCheck = false;

    passthru = {
      inherit cargoArtifacts commonArgs;

      gccWrappers = [
        gccWrapper
        gppWrapper
      ];
    };

    doInstallCheck = true;
    nativeInstallCheckInputs = [ versionCheckHook ];
    versionCheckProgramArg = "--version";

    meta = {
      changelog = "https://github.com/davidlattimore/wild/blob/${commonArgs.version}/CHANGELOG.md";
      description = "A very fast linker for Linux";
      homepage = "https://github.com/davidlattimore/wild";
      license = [
        lib.licenses.asl20 # or
        lib.licenses.mit
      ];
      mainProgram = "wild";
      platforms = lib.platforms.linux;
    };
  }
)
