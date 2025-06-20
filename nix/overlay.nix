# TODO(RossSmyth): One 1.87 is on nixpkgs unstable, remove the rust-overlay requirement.
crane: final: prev:
let
  craneLib = (crane.mkLib final).overrideToolchain (p: p.rust-bin.beta.latest.minimal);
in
{
  wild = final.callPackage ./. { inherit craneLib; };
  useWildLinker = import ./adapter.nix {
    pkgs = final;
    lib = final.lib;
  };
}
