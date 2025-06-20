{
  inputs = {
    nixpkgs.url = "https://nixos.org/channels/nixos-unstable/nixexprs.tar.xz";
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
    }:
    let
      forAllSystems = nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed;

      common = forAllSystems (system: rec {
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            (import self)
          ];
        };

        craneLib = crane.mkLib pkgs;
      });
    in
    {
      packages = forAllSystems (
        system:
        let
          inherit (common.${system}) pkgs craneLib;
        in
        {
          default = pkgs.callPackage ./nix { inherit craneLib; };
        }
      );

      overlays.default = import self;

      formatter = forAllSystems (system: common.${system}.pkgs.nixfmt-tree);

      checks = forAllSystems (
        system:
        let
          inherit (common.${system}) pkgs craneLib;
          inherit (self.packages.${system}) default;
        in
        {
          wild = default.overrideAttrs {
            doCheck = true;
            doInstallCheck = false;
            # Skip the build phase and don't install anything
            # because it ends up building libwild twice. Once for the buildPhase,
            # once for the checkPhase.
            dontBuild = true;
            installPhase = "touch $out";
          };
        }
        // ((pkgs.callPackage ./nix { inherit craneLib; }).tests)
      );

      devShells = forAllSystems (system: {
        default = common.${system}.pkgs.callPackage ./nix/shell.nix {
          inherit (common.${system}) craneLib;
        };
      });
    };
}
