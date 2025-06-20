final: prev:
let
  craneNodes = (builtins.fromJSON (builtins.readFile ./flake.lock)).nodes.crane.locked;

  craneSrc = import (
    final.fetchFromGitHub {
      inherit (craneNodes) owner repo rev;
      hash = craneNodes.narHash;
    }
  );
in
import ./nix/overlay.nix { mkLib = pkgs: craneSrc { inherit pkgs; }; } final prev
