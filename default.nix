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
    haskellNix.nixpkgsArgs;

  hlib = pkgs.haskell-nix.haskellLib;
in pkgs.pkgsCross.musl64.haskell-nix.project {
  cabalProjectLocal = null;
  src = pkgs.haskell-nix.haskellLib.cleanGit {
    name = "powerdns-gerd";
    src = ./.;
  };
  compiler-nix-name = "ghc925";
  index-state = "2023-02-08T00:00:00Z";
}
