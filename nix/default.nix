{
  lib,
  craneLib,
  versionCheckHook,
  rustc,
  callPackage,
  path,
  lld,
  clang,
  clang-tools,
  binutils-unwrapped-all-targets,
  glibc,
  stdenv,
}:
assert lib.assertMsg (lib.versionAtLeast rustc.version "1.93.0")
  "Wild requires at least Rust 1.93.0, this instance of nixpkgs has Rust ${rustc.version}";

let
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
  };

  inherit (callPackage ./wrappers.nix { }) gccWrapper gppWrapper;
in
craneLib.buildPackage (
  commonArgs
  // {
    cargoArtifacts = craneLib.buildDepsOnly commonArgs;
    cargoBuildCommand = "cargo build --profile release -p wild-linker";

    # Do the check in the separate derivation so it can be done
    # in parallel in the dev profile
    doCheck = false;
    nativeCheckInputs = [
      lld
      clang
      clang-tools
      binutils-unwrapped-all-targets
      gccWrapper
      gppWrapper
    ];
    checkInputs = [
      glibc.out
      glibc.static
    ];

    env.LD_LIBRARY_PATH = lib.makeLibraryPath [
      stdenv.cc.cc.lib
    ];

    # Do the install check instead just as a smoke-tests that Wild
    # built correctly.
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
