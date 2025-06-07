# TODO(RossSmyth): One 1.87 is on nixpkgs unstable, remove the rust-overlay requirement.
final: prev:
let
  rustToolchain = final.rust-bin.beta.latest.minimal;
  rustPlatform = final.makeRustPlatform {
    rustc = rustToolchain;
    cargo = rustToolchain;
  };
in
{
  wild = final.callPackage ./. { inherit rustPlatform; };
  useWildLinker = import ./adapter.nix {
    pkgs = final;
    lib = final.lib;
  };
}
