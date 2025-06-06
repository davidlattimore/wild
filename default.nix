{
  lib,
  pkgs,
  stdenv,
  gccStdenv,
  clangStdenv,
  fetchpatch,
  makeBinaryWrapper,
  rustPlatform,
  nix-update-script,
  versionCheckHook,
  buildPackages,
  runCommandCC,
  testers,
  hello,
  clang,
  binutils-unwrapped-all-targets,
  gcc,
  glibc,
  lld,
}:
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

  cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);

  fs = lib.fileset;

  # Only track files checked into git, and then specify files to ignore that
  # are tracked in git too.
  # This can reduce rebuilds with Nix.
  files = fs.difference (fs.gitTracked ./.) (
    fs.unions [
      ./.gitignore
      ./flake.lock
      ./docker
      ./test-config.toml.sample
      ./test-config-ci.toml
      ./.dockerignore
      ./cackle.toml
      ./dist-workspace.toml
      ./rustfmt.toml
      ./LICENSE-MIT
      ./LICENSE-APACHE
      (fs.fileFilter (file: file.hasExt "md") ./.)
      (fs.fileFilter (file: file.hasExt "nix") ./.)
    ]
  );
in
rustPlatform.buildRustPackage (finalAttrs: {
  inherit (cargoToml.workspace.package) version;

  strictDeps = true;
  pname = "wild";

  src = fs.toSource {
    root = ./.;
    fileset = files;
  };

  patches = [
    (fetchpatch {
      url = "https://github.com/davidlattimore/wild/pull/831.patch";
      hash = "sha256-UywEVaaqnin0PBsRqDLIZXSI6QdtQ9WHetuQrAfUlNo=";
    })
  ];

  useFetchCargoVendor = true;
  cargoLock = {
    lockFile = ./Cargo.lock;
    allowBuiltinFetchGit = true;
  };

  cargoBuildFlags = [ "-p wild-linker" ];

  # wild's tests compare the outputs of several different linkers. nixpkgs's
  # patching and wrappers change the output behavior, so we must make sure
  # that their behavior is compatible.
  doCheck = false;
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
        gccWrapper
        gppWrapper
        lld
      ]
    }:$PATH
  '';

  passthru = {
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
          hello.override (_: {
            stdenv = useWildLinker gccStdenv;
          })
        );

        adapterClang = helloTest "adapter-clang" (
          hello.override {
            stdenv = useWildLinker clangStdenv;
          })
        );
      };
  };

  doInstallCheck = true;
  nativeInstallCheckInputs = [ versionCheckHook ];
  versionCheckProgramArg = "--version";

  meta = {
    changelog = "https://github.com/davidlattimore/wild/blob/${finalAttrs.version}/CHANGELOG.md";
    description = "A very fast linker for Linux";
    homepage = "https://github.com/davidlattimore/wild";
    license = [
      lib.licenses.asl20 # or
      lib.licenses.mit
    ];
    mainProgram = "wild";
    platforms = lib.platforms.linux;
  };
})
