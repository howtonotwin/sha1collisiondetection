{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };
  outputs = { self, nixpkgs }: let
    inherit (nixpkgs) lib;
    forSystems = systems: outputs: lib.zipAttrsWith
      (type: lib.mergeAttrsList)
      (lib.map
        (system: lib.mapAttrs
          (type: value: { ${system} = value; })
          (lib.fix (systemOutputs:
            outputs system (self // systemOutputs))))
        systems);
    extendPackage = pkgs: pkg: openMkPkg: let
      mkPkgImpl = args: let
        oldArgs = lib.intersectAttrs (lib.functionArgs pkg.override) args;
        old     = pkg.override oldArgs;
      in openMkPkg args old;
      mkPkg =
        lib.setFunctionArgs
          mkPkgImpl
          (lib.functionArgs pkg.override // lib.functionArgs openMkPkg);
    in pkgs.callPackage mkPkg { };
  in {
    overlays.default = final: prev: {
      sha1collisiondetection = prev.sha1collisiondetection.overrideAttrs (final: prev: {
        __structuredAttrs = true;
        version = "1.0.3-unstable-2026-10-04";
        src = lib.fileset.toSource {
          root    = ./.;
          fileset = lib.fileset.unions [
            ./lib ./src ./test
            ./Makefile ./LICENSE.txt
          ];
        };
        enableParallelBuilding = true;
        meta = prev.meta // {
          homepage = "https://github.com/howtonotwin/sha1collisiondetection";
        };
      });
      git = extendPackage final prev.git (
        {
          sha1collisiondetection,
          withSha1collisiondetection ? false,
          ...
        }@args: old: old.overrideAttrs (
          final: prev: let
            flag     = withSha1collisiondetection;
            maybeAdd = name: x: {
              ${if prev ? ${name} || flag then name else null} =
                prev.${name} or [ ] ++ lib.optional flag x;
            };
          in maybeAdd "buildInputs" sha1collisiondetection
            // maybeAdd "makeFlags" "DC_SHA1_EXTERNAL=YesPlease"));
    };
  } // forSystems lib.platforms.linux (system: self: let
    pkgs = import nixpkgs {
      inherit system;
      overlays = [ self.overlays.default ];
    };
  in {
    packages = {
      default = self.packages.sha1collisiondetection;
      inherit (pkgs) sha1collisiondetection;
      git = pkgs.git.override {
        withSha1collisiondetection = true;
      };
    };
  });
}
