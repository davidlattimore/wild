# Nix

Wild include a flake, a derivation for building Wild, and a stdenv adapter
in-tree. If the overlay is applied these are provided for you. Just add it to
your flake inputs. A devShell example is also shown with the flake.

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    wild = {
      url = "github:davidlattimore/wild";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      wild,
    }:
    let
      pkgs = import nixpkgs {
        system = "x86_64-linux";
        overlays = [
          (import wild)
        ];
      };

      wildStdenv = pkgs.useWildLinker pkgs.stdenv;
    in
    {
      packages.x86_64-linux.default = pkgs.callPackage ./package.nix { stdenv = wildStdenv; };

      devShell.x86_64-linux.default = pkgs.mkShell.override { stdenv = wildStdenv; } {
        inputsFrom = [ self.packages.x86_64-linux.default ];
        packages = [
          pkgs.rust-analyzer
        ];
      };
    };
}
```
Without flakes (npins shown):

1. `$ npins add github davidlattimore wild -b main`

```nix
let
  sources = import ./npins;
  pkgs = import sources.nixpkgs {
    overlays = [
      (import sources.wild)
    ];
  };
  wildStdenv = pkgs.useWildLinker pkgs.stdenv;
in
{
  package = pkgs.callPackage ./package.nix { stdenv = wildStdenv; };
}
```
