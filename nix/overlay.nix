crane: final: prev:
let
  craneLib = crane.mkLib final;
in
{
  wild = final.callPackage ./. { inherit craneLib; };
  useWildLinker = import ./adapter.nix {
    pkgs = final;
    lib = final.lib;
  };
}
