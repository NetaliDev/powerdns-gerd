{
  inputs = {
    nixpkgs.follows = "haskellNix/nixpkgs-unstable";
    haskellNix.url = "github:input-output-hk/haskell.nix";
  };

  outputs = { self, nixpkgs, haskellNix, ... }@inputs: let
    overlays = [ haskellNix.overlay
        (final: prev: {
          powerdns-gerd =
            final.haskell-nix.project' {
              cabalProjectLocal = null;
              src = ./.; 
              plan-sha256 = "19nzj3ggciakml718j64lqbh3jdzd5xmkibiznr58dw26p9c8ngn";
              materialized = ./powerdns-gerd.materialized;
              compiler-nix-name = "ghc925";
              index-state = "2023-02-08T00:00:00Z";
            };
        })
      ];
      pkgs = import nixpkgs { inherit overlays; inherit (haskellNix) config; system = "x86_64-linux"; };
      flake = pkgs.powerdns-gerd.flake {};

  in flake // {
    packages.x86_64-linux.default = flake.packages."powerdns-gerd:exe:powerdns-gerd";
    packages.x86_64-linux.powerdns-gerd = flake.packages."powerdns-gerd:exe:powerdns-gerd";

    hydraJobs.powerdns-gerd.x86_64-linux = flake.packages."powerdns-gerd:exe:powerdns-gerd";
  };

}
