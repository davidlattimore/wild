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

  outputs = { self, nixpkgs, wild }:
    let
      forAllSystems = nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed;
    in
    {
      packages = forAllSystems (system: {
        default = wild.packages.${system}.default;
      });

      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          wildStdenv = pkgs.useWildLinker pkgs.stdenv;
        in
        {
          default = pkgs.mkShell.override { stdenv = wildStdenv; } {
            inputsFrom = [ self.packages.${system}.default ];
            packages = [ pkgs.rust-analyzer ];
          };
        }
      );
    };
}
```
Without flakes (npins shown):

1. `$ npins add github davidlattimore wild -b main`

```nix
let
  sources = import ./npins;
  pkgs = import sources.nixpkgs { };
  wildStdenv = pkgs.useWildLinker pkgs.stdenv;
in
{
  package = pkgs.callPackage ./package.nix { stdenv = wildStdenv; };
}
```
