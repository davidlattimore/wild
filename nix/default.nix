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
assert lib.assertMsg (lib.versionAtLeast "1.89.0" pkgs.rustc.version)
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
      ../dist-workspace.toml
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
      tests =
        let
          helloTest =
            name: helloWild:
            let
              command = "$READELF -p .comment ${lib.getExe helloWild}";
              emulator = stdenv.hostPlatform.emulator buildPackages;
            in
            runCommandCC "wild-${name}-test" { passthru = { inherit helloWild; }; } ''
              echo "Testing running the 'hello' binary which should be linked with 'wild'" >&2
              ${emulator} ${lib.getExe helloWild}
              echo "Checking for wild in the '.comment' section" >&2
              if output=$(${command} 2>&1); then
                if grep -Fw -- "Wild" - <<< "$output"; then
                  touch $out
                else
                  echo "No mention of 'wild' detected in the '.comment' section" >&2
                  echo "The command was:" >&2
                  echo "${command}" >&2
                  echo "The output was:" >&2
                  echo "$output" >&2
                  exit 1
                fi
              else
                echo -n "${command}" >&2
                echo " returned a non-zero exit code." >&2
                echo "$output" >&2
                exit 1
              fi
            '';

          useWildLinker = import ./adapter.nix { inherit pkgs lib; };
        in
        lib.optionalAttrs stdenv.hostPlatform.isLinux {
          adapterGcc = helloTest "adapter-gcc" (
            hello.override {
              stdenv = useWildLinker gccStdenv;
            }
          );

          adapterClang = helloTest "adapter-clang" (
            hello.override {
              stdenv = useWildLinker clangStdenv;
            }
          );
        };
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
