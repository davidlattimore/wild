final: prev:
let
  # Get Crane out of the lockfile
  craneNodes = (builtins.fromJSON (builtins.readFile ./flake.lock)).nodes.crane.locked;
  craneSrc = final.fetchFromGitHub {
    inherit (craneNodes) owner repo rev;
    hash = craneNodes.narHash;
  };

  craneLib = import craneSrc { pkgs = final; };
in
{
  wild-unwrapped = final.callPackage ./nix { inherit craneLib; };
}
