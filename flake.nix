{
  inputs = {
    nixpkgs.url = "https://nixos.org/channels/nixos-unstable/nixexprs.tar.xz";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      system = "x86_64-linux";

      pkgs = import nixpkgs {
        inherit system;
        overlays = [ (import rust-overlay) ];
      };
      # TODO: once rust 1.87 (nixos/nixpkgs#407444) hits unstable
      # and davidlattimore/wild#831 no longer depends on rust nightly,
      # we should switch to the standard nixpkgs rustPlatform
      rustToolchain = pkgs.rust-bin.beta.latest.minimal;
      rustPlatform = pkgs.makeRustPlatform {
        rustc = rustToolchain;
        cargo = rustToolchain;
      };
    in
    {
      lib.useWildLinker = import ./adapter.nix {
        inherit pkgs;
        inherit (pkgs) lib;
      };
      packages.${system}.default = pkgs.callPackage ./. { inherit rustPlatform; };

      overlays.default = final: prev: {
        wild = final.callPackage ./. { inherit rustPlatform; };
        useWildLinker = import ./adapter.nix {
          pkgs = final;
          lib = final.lib;
        };
      };

      formatter.${system} = pkgs.nixfmt-tree;

      checks.${system} =
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ self.overlays.default ];
          };
        in
        {
          wild = self.packages.${system}.default.overrideAttrs { doCheck = true; };
        }
        // ((pkgs.callPackage ./. { inherit rustPlatform; }).tests);

      devShells.${system}.default = pkgs.callPackage ./shell.nix { };
    };
}
