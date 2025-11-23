# Nix

Wild includes a Nix flake, an overlay, and a derivation for building Wild.
this allows users to use the latest git revision of Wild without having to
wait for a release to be packaged in Nixpkgs.

There are two ways of using an unstable Wild, one is with Nix Flakes. Note that
until NixOS 25.11 is branched, unstable Nixpkgs is required.

```nix
{
  inputs = {
    # Have Nixpkgs
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Include Wild
    wild = {
      url = "github:davidlattimore/wild";
      # If using the Wild Flake (not required)
      # inputs.nixpkgs.follows = "nixpkgs";
      #
      # If not using the Wild flake, and just using the overlay
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      wild,
    }:
    let
      # Create an instance of Nixpkgs targeting x64 Linux with the
      # Wild overlay applied
      pkgs = import nixpkgs {
        system = "x86_64-linux";
        overlays = [
          (import wild)
        ];
      };

      # Create a stdenv that uses the Wild linker
      wildStdenv = pkgs.useWildLinker pkgs.stdenv;
    in
    {
      # Add an output of some very cool package that is linked with the Wild linker
      #
      # Note that if a Rust package is being linked with `buildRustPackage`, you will
      # need to create a `rustPlatform` using `makeRustPlatform` with this stdenv. See
      # below how to do that.
      packages.x86_64-linux.default = pkgs.callPackage ./package.nix { stdenv = wildStdenv; };

      # A devShell for the very cool package that uses Wild.
      #
      # It also has rust-analyzer in its environment
      devShell.x86_64-linux.default = pkgs.mkShell.override { stdenv = wildStdenv; } {
        inputsFrom = [ self.packages.x86_64-linux.default ];
        packages = [
          pkgs.rust-analyzer
        ];
      };
    };
}
```
Without flakes (npins shown, but any solution can be used):

Add the dependencies to lockfile with npins: `$ npins add github davidlattimore wild -b main`

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
  # C Package
  package = pkgs.callPackage ./package.nix { stdenv = wildStdenv; };
}
```
If building a Rust package with `rustPlatform.buildRustPackage`, a little more
setup is required. This applies to Flake-based packages, or other solutions.

```nix
let
  # First steps are the same as above. Create a Nixpkgs instance
  # with Wild.
  pkgs = import nixpkgs {
    system = "x86_64-linux";
    overlays = [
      (import wild)
    ];
  };

  # Create a stdenv that uses Wild as its linker
  wildStdenv = pkgs.useWildLinker pkgs.stdenv;

  # Next a custom rustPlatform is required.
  #
  # This uses Nixpkgs rustc and cargo, but uses
  # the stdenv that has Wild.
  wildRustPlatform = pkgs.makeRustPlatform {
    inherit (pkgs) rustc cargo;
    stdenv = wildStdenv;
  };
in
# Then create whatever cool package you are building
callPackage ./package.nix { rustPlatform = wildRustPlatform; }
```
