{ mode }:
let
  # Read in the Niv sources
  sources = import nix/sources.nix {};

  # Fetch the haskell.nix commit we have pinned with Niv
  haskellNix = import sources.haskellNix {};
  # If haskellNix is not found run:
  #   niv add input-output-hk/haskell.nix -n haskellNix

  # Import nixpkgs and pass the haskell.nix provided nixpkgsArgs
  pkgs = import
    # haskell.nix provides access to the nixpkgs pins which are used by our CI,
    # hence you will be more likely to get cache hits when using these.
    # But you can also just use your own, e.g. '<nixpkgs>'.
    haskellNix.sources.nixpkgs-unstable

    # These arguments passed to nixpkgs, include some patches and also
    # the haskell.nix functionality itself as an overlay.
    (haskellNix.nixpkgsArgs // { system = "x86_64-linux"; }) ;

  hlib = pkgs.haskell-nix.haskellLib;
  overlaidPkgs = if mode == "static" then pkgs.pkgsCross.musl64
                 else if mode == "dynamic" then pkgs
                 else throw ''mode must be "dynamic" or "static"'';
in overlaidPkgs.haskell-nix.project {
  cabalProjectLocal = null;
  src = pkgs.haskell-nix.haskellLib.cleanGit {
    name = "powerdns-gerd";
    src = ./.;
  };
  checkMaterialization = true;
  plan-sha256 = "19nzj3ggciakml718j64lqbh3jdzd5xmkibiznr58dw26p9c8ngn";
  materialized = ./powerdns-gerd.materialized;
  compiler-nix-name = "ghc925";
  index-state = "2023-02-08T00:00:00Z";
}
