crane: final: prev:
let
  craneLib = crane.mkLib final;
in
{
  wild-unwrapped = final.callPackage ./. { inherit craneLib; };
}
