{
  lib,
  pkgs,
}:
stdenv:
if !stdenv.targetPlatform.isLinux then
  throw "Wild only supports Linux"
else
  let
    bintools = stdenv.cc.bintools.override {
      extraBuildCommands = ''
        wrap ld.wild ${pkgs.path}/pkgs/build-support/bintools-wrapper/ld-wrapper.sh ${pkgs.buildPackages.wild}/bin/wild
        wrap ${stdenv.cc.bintools.targetPrefix}ld.wild ${pkgs.path}/pkgs/build-support/bintools-wrapper/ld-wrapper.sh ${pkgs.buildPackages.wild}/bin/wild
        wrap ${stdenv.cc.bintools.targetPrefix}ld ${pkgs.path}/pkgs/build-support/bintools-wrapper/ld-wrapper.sh ${pkgs.buildPackages.wild}/bin/wild
      '';
    };
  in
  stdenv.override (_: {
    allowedRequisites = null;
    cc = stdenv.cc.override { inherit bintools; };
  })
