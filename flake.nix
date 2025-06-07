{
  inputs = {
    nixpkgs.url = "https://nixos.org/channels/nixos-unstable/nixexprs.tar.xz";

    # TODO: once rust 1.87 (nixos/nixpkgs#407444) hits unstable
    # and davidlattimore/wild#831 no longer depends on rust nightly,
    # we should switch to the standard nixpkgs rustPlatform
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
      forAllSystems = nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed;

      common = forAllSystems (system: {
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            self.overlays.default
            (import rust-overlay)
          ];
        };

        rustToolchain = common.${system}.pkgs.rust-bin.beta.latest.minimal;
        rustPlatform = common.${system}.pkgs.makeRustPlatform {
          rustc = common.${system}.rustToolchain;
          cargo = common.${system}.rustToolchain;
        };
      });
    in
    {
      packages = forAllSystems (
        system:
        let
          inherit (common.${system}) pkgs rustPlatform;
        in
        {
          default = pkgs.callPackage ./nix { inherit rustPlatform; };
        }
      );

      overlays.default = import ./nix/overlay.nix;

      formatter = forAllSystems (system: common.${system}.pkgs.nixfmt-tree);

      checks = forAllSystems (
        system:
        let
          inherit (common.${system}) pkgs rustPlatform;
        in
        {
          wild = self.packages.${system}.default.overrideAttrs { doCheck = true; };
        }
        // ((pkgs.callPackage ./nix { inherit rustPlatform; }).tests)
      );

      devShells = forAllSystems (system: {
        default = common.${system}.pkgs.callPackage ./nix/shell.nix { };
      });
    };
}
